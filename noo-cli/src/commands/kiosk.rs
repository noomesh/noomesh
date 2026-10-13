// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo kiosk setup|status|teardown` — the display's host seat.
//!
//! The kiosk is a viewer, not a node: a Linux box with a
//! screen and no keyboard, showing `/kiosk.html` from the controller over
//! the tailnet. Nothing from the repo is installed on it. What this command
//! puts there is the SEAT — a `kiosk` user, `cage` + Chromium under a
//! systemd unit on tty1, a launcher that mints a short-lived token and
//! injects it over CDP, and a watchdog timer that renews the token,
//! reloads a stale page and restarts a dead session.
//!
//! **The display holds no durable secret.** It mints by proving its
//! tailnet identity: it serves a nonce on its own tailnet address for the
//! seconds a mint takes, and the controller comes to read it. WireGuard
//! routing means only the true owner of that address can answer, so the
//! nonce IS the proof. Same admission as node enrollment, applied to a
//! viewer.
//!
//! The honest cost is availability, not secrecy. A stored key needed only
//! outbound reach to mint; this needs the tailnet working in BOTH
//! directions at every renewal, so it has more ways to go dark — and it
//! goes dark rather than leaking, which is the trade.
//!
//! Two refusals are the design, not caution:
//! - the URL must be the tailscale-serve `ts.net` URL, never `:8080`.
//!   Chromium on Linux ignores the OS trust store; the cluster CA would
//!   put a certificate wall on a screen nobody can dismiss (§4.2);
//! - the browser must be a non-snap Chromium-family build (the `chromium` .deb on Debian, Google Chrome or a PPA .deb on Ubuntu): snap Chromium
//!   relocates the profile and `~/.pki`, so the user-data-dir this seat
//!   points at is not the one it runs with.
//!
//! Attended: installs go through `sudo install` / `sudo systemctl` and
//! prompt on the operator's tty, the same posture as `upgrade --controller`.

use serde_json::json;

use crate::output::{fail, ExitCode};
use crate::ui;
use crate::{Globals, Unhandled};

const LAUNCH: &str = include_str!("kiosk_assets/noo-kiosk-launch");
const CDP: &str = include_str!("kiosk_assets/noo-kiosk-cdp");
const WATCHDOG: &str = include_str!("kiosk_assets/noo-kiosk-watchdog");
const SERVE: &str = include_str!("kiosk_assets/noo-kiosk-serve");

pub const ENV_FILE: &str = "/etc/default/kiosk";
pub const STATE_DIR: &str = "/var/lib/kiosk";
const BIN_DIR: &str = "/usr/local/bin";
const UNIT_DIR: &str = "/etc/systemd/system";
const LOGIND_CONF: &str = "/etc/systemd/logind.conf.d/kiosk.conf";

/// The dialback port: where the display serves its proof nonce while a
/// mint is in flight, and nowhere else in its life. Must match the
/// `tag:controller -> tag:kiosk:<port>` grant in
/// `config/tailscale-acl.hujson`; a test asserts they agree.
pub(crate) const DIALBACK_PORT: u16 = 8099;

/// The local proxy's port, on 127.0.0.1 and nowhere else.
///
/// This is the ONLY address the browser knows. The page holds no
/// credential (`ui/apps/web/src/kiosk/main.tsx` says so and names
/// `noo kiosk serve`), so something has to attach one, and it is this —
/// on the device, not in the DOM of a machine standing in a corridor.
pub(crate) const PROXY_PORT: u16 = 8088;

// ── arguments ──────────────────────────────────────────────────────────

/// Which shape of machine this display is. **There is no default**: the two
/// differ in whether the box remains a usable computer afterwards, and
/// guessing that for someone is how a laptop gets dismantled by surprise.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Mode {
    /// The box is a display and nothing else. The kiosk owns tty1, the
    /// display manager is disabled, and the login terminals are shut off,
    /// so there is nothing behind the dashboard to escape to.
    Dedicated,
    /// The box is still a laptop that also shows a dashboard. Nothing is
    /// dismantled: the desktop keeps tty1, the login terminals stay, and
    /// the kiosk takes a free VT of its own.
    Shared,
}

impl Mode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Dedicated => "dedicated",
            Mode::Shared => "shared",
        }
    }
}

/// The VT a shared-mode display runs on. tty1 belongs to the desktop and 7
/// is conventionally the graphical session, so 8 is the first comfortably
/// free one. `--vt` overrides.
pub(crate) const SHARED_DEFAULT_VT: u8 = 8;

/// Dedicated mode always takes tty1 — it is the VT a getty and a greeter
/// would otherwise claim, and taking it is the point.
pub(crate) const DEDICATED_VT: u8 = 1;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SetupArgs {
    pub url: String,
    pub user: String,
    pub view: String,
    pub rotate: Option<u32>,
    /// `--poll`: seconds between graph re-fetches, as `?poll=N`.
    ///
    /// The page holds a live stream, so nothing here is needed for the
    /// health view. The GRAPH is the exception: the gateway has no
    /// `graph.delta` event yet, so an ingest is invisible until the
    /// stream reconnects — which on a working display is never. Until
    /// that event exists, this is how a graph screen notices new data.
    pub poll: Option<u32>,
    /// `--quality lean|full`: pins the graph's drawing quality, as
    /// `?quality=`. Unset, the page measures its own frames and degrades
    /// on a machine that cannot keep up (host5's Quadro FX 1700 put
    /// Chromium in software rendering). This exists so the operator's
    /// decision is one the seat can hold across a restart — a parameter
    /// only reachable by driving the browser by hand is not a setting.
    pub quality: Option<String>,
    pub dry_run: bool,
    /// `-y/--yes`: consent to disabling the display manager (dedicated mode).
    /// It does NOT consent to masking the getty; that always asks.
    pub yes: bool,
    /// `--browser`: a Chromium-family binary name or path. None = probe the
    /// known names. Ubuntu ships no .deb Chromium, so an operator there
    /// installs Google Chrome or a PPA build and names it here.
    pub browser: Option<String>,
    /// `--mode`. Required; see [`Mode`].
    pub mode: Mode,
    /// The VT the seat runs on: tty1 in dedicated mode, `--vt` or
    /// [`SHARED_DEFAULT_VT`] in shared.
    pub vt: u8,
}

pub(crate) fn parse_setup(args: &[String]) -> Result<SetupArgs, String> {
    let mut url = None;
    let mut user = "kiosk".to_string();
    let mut view = "health".to_string();
    let mut rotate = None;
    let mut poll = None;
    let mut quality: Option<String> = None;
    let mut browser: Option<String> = None;
    let mut dry_run = false;
    let mut yes = false;
    let mut mode: Option<Mode> = None;
    let mut vt: Option<u8> = None;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--url" => url = Some(it.next().ok_or("--url needs a value")?.clone()),
            // Retired with the keyless mint. Refuse loudly rather than
            // ignore: an operator pasting an old command would otherwise
            // believe a key was stored, and the display would work anyway
            // (it mints by tailnet proof), leaving them with a wrong model
            // of what the box holds.
            "--key" | "--key-stdin" => {
                return Err(
                    "--key/--key-stdin are retired: the display stores no durable secret. It \
                     mints its token by proving its tailnet identity, so `noo kiosk invite \
                     <display-name>` issues no key to pass here. Revoke any old kiosk service key with \
                     `noo security service-key revoke kiosk-<name>`."
                        .into(),
                )
            }
            "--user" => user = it.next().ok_or("--user needs a value")?.clone(),
            "--view" => view = it.next().ok_or("--view needs a value")?.clone(),
            "--rotate" => {
                let v = it.next().ok_or("--rotate needs a value")?;
                rotate = Some(v.parse::<u32>().map_err(|_| format!("--rotate: not a number of seconds: {v}"))?);
            }
            "--poll" => {
                let v = it.next().ok_or("--poll needs a value")?;
                poll = Some(v.parse::<u32>().map_err(|_| format!("--poll: not a number of seconds: {v}"))?);
            }
            "--quality" => {
                let v = it.next().ok_or("--quality needs a value: lean or full")?;
                match v.as_str() {
                    "lean" | "full" => quality = Some(v.clone()),
                    other => return Err(format!("--quality must be lean or full, not {other}")),
                }
            }
            "--dry-run" => dry_run = true,
            "-y" | "--yes" => yes = true,
            "--browser" => browser = Some(it.next().ok_or("--browser needs a value")?.clone()),
            "--mode" => {
                let v = it.next().ok_or("--mode needs a value: dedicated or shared")?;
                mode = Some(match v.as_str() {
                    "dedicated" => Mode::Dedicated,
                    "shared" => Mode::Shared,
                    other => return Err(format!("--mode must be dedicated or shared, not {other}")),
                });
            }
            "--vt" => {
                let v = it.next().ok_or("--vt needs a value")?;
                let n = v.parse::<u8>().map_err(|_| format!("--vt: not a terminal number: {v}"))?;
                if !(2..=63).contains(&n) {
                    return Err(format!(
                        "--vt {n}: pick 2–63. tty1 belongs to the desktop in shared mode — taking \
                         it is what dedicated mode is for"
                    ));
                }
                vt = Some(n);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let url = url.ok_or("--url <https://…ts.net…> is required")?;
    // No default. The two modes differ in whether this machine is still
    // usable afterwards, and choosing that for someone is how a laptop
    // loses its desktop to a dashboard.
    let mode = mode.ok_or(
        "--mode is required: `dedicated` (the box is a display and nothing else — the desktop \
         and the login terminals are shut off) or `shared` (the box stays a laptop; the display \
         takes a spare terminal you switch to). There is no default because the two differ in \
         whether this machine is still usable afterwards.",
    )?;
    if vt.is_some() && mode == Mode::Dedicated {
        return Err(format!(
            "--vt is for --mode shared. A dedicated display takes tty{DEDICATED_VT} on purpose: \
             it is the terminal a getty and a greeter would otherwise claim"
        ));
    }
    let vt = match mode {
        Mode::Dedicated => DEDICATED_VT,
        Mode::Shared => vt.unwrap_or(SHARED_DEFAULT_VT),
    };
    if !matches!(view.as_str(), "health" | "graph") {
        return Err(format!("--view must be health or graph, not {view}"));
    }
    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') || user.is_empty() {
        return Err(format!("--user: not a valid unix user name: {user}"));
    }
    Ok(SetupArgs {
        url: url.trim_end_matches('/').to_string(),
        user, view, rotate, poll, quality, dry_run, yes, browser, mode, vt,
    })
}

/// The URL the display will show. `https`, and never the gateway's own
/// `:8080` — that listener carries the cluster-PKI leaf, which Chromium
/// does not trust (it keeps its own NSS store; `noo security trust-ca`
/// only teaches the OS one). The `tailscale serve` URL carries a public
/// certificate, and nothing else about the seat changes.
pub(crate) fn validate_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err(format!("the kiosk URL must be https (got {url})"));
    }
    let hostport = url.trim_start_matches("https://").split('/').next().unwrap_or("");
    if hostport.ends_with(":8080") {
        return Err(format!(
            "{url} is the gateway's own listener. It serves the cluster-PKI certificate, which \
             Chromium does not trust (it ignores the OS store), so the screen would show a \
             certificate wall nobody can dismiss. Use the `tailscale serve` URL for the controller \
             (https://<controller>.<tailnet>.ts.net), which carries a public certificate."
        ));
    }
    if hostport.is_empty() {
        return Err("the kiosk URL has no host".into());
    }
    Ok(())
}

// ── rendered files ─────────────────────────────────────────────────────

pub(crate) fn render_env(a: &SetupArgs) -> String {
    let rotate = a.rotate.map(|r| r.to_string()).unwrap_or_default();
    let poll = a.poll.map(|p| p.to_string()).unwrap_or_default();
    let quality = a.quality.clone().unwrap_or_default();
    format!(
        "# Written by `noo kiosk setup`. root:{user} 0640 — the kiosk user reads it,\n\
         # nobody else.\n\
         #\n\
         # THERE IS NO KEY HERE, and that is the design. The display mints its\n\
         # short-lived token by proving its tailnet identity: it publishes a\n\
         # nonce on its own tailnet address and the controller comes to read\n\
         # it. Nothing durable sits on a machine in a corridor.\n\
         #\n\
         # NOO_KIOSK_DIALBACK_PORT is the port that nonce is served on, for\n\
         # the seconds a mint takes. The tailnet policy grants\n\
         # tag:controller -> tag:kiosk on it and nothing else reaches it.\n\
         NOO_KIOSK_URL={url}\n\
         NOO_KIOSK_VIEW={view}\n\
         NOO_KIOSK_ROTATE={rotate}\n\
         NOO_KIOSK_POLL={poll}\n\
         NOO_KIOSK_QUALITY={quality}\n\
         NOO_KIOSK_STATE={state}\n\
         NOO_KIOSK_USER={user}\n\
         NOO_KIOSK_DIALBACK_PORT={dialback}\n\
         NOO_KIOSK_SERVE_PORT={proxy}\n\
         NOO_KIOSK_MODE={mode}\n\
         NOO_KIOSK_VT={vt}\n",
        user = a.user, url = a.url, view = a.view, quality = quality, state = STATE_DIR,
        dialback = DIALBACK_PORT, proxy = PROXY_PORT,
        mode = a.mode.as_str(), vt = a.vt,
    )
}

/// The local proxy's unit. Starts BEFORE the browser and stays up.
///
/// `Requires=` rather than `Wants=` on the browser's side: a display
/// whose proxy is down is a browser pointed at a closed port, which
/// renders a Chrome error page. The page's own "credential rejected"
/// band — which the proxy produces by answering 401 when its mint fails
/// — is a display saying what is wrong. Those are different outcomes and
/// only one of them is useful from across a room.
pub(crate) fn render_serve_service(user: &str) -> String {
    format!(
        "# Written by `noo kiosk setup`. The browser's only hop.\n\
         #\n\
         # Holds the credential so the page does not: it mints by proving\n\
         # this display's tailnet identity and attaches the bearer to the\n\
         # reads the dashboard is allowed to make. The browser talks to\n\
         # 127.0.0.1 and never learns the controller URL.\n\
         [Unit]\n\
         Description=noomesh kiosk local proxy (holds the credential; the browser does not)\n\
         After=network-online.target tailscaled.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         EnvironmentFile={env}\n\
         ExecStart={bin}/noo-kiosk-serve\n\
         Restart=always\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = user, env = ENV_FILE, bin = BIN_DIR,
    )
}

/// The seat's unit. `cage` on a VT as the kiosk user; the PAM session is
/// what gives the compositor its seat (cage's own systemd recipe).
///
/// **What differs by mode is what the unit CONFLICTS with, and that is the
/// whole safety question.** In dedicated mode it conflicts with the tty1
/// getty AND the display manager, because a greeter on tty1 is a lock
/// screen the display can never get past and a desktop session would
/// idle-lock over the top of it. In shared mode it conflicts with NOTHING:
/// the desktop keeps tty1 and its greeter, and the kiosk takes a free VT.
/// A shared unit that named `display-manager.service` would take the
/// laptop's desktop away on the next boot, which is exactly what shared
/// mode exists to avoid.
pub(crate) fn render_kiosk_service(user: &str, mode: Mode, vt: u8) -> String {
    let conflicts = match mode {
        Mode::Dedicated => format!("Conflicts=getty@tty{vt}.service display-manager.service\n"),
        // Deliberately none. See the doc comment.
        Mode::Shared => String::new(),
    };
    let why = match mode {
        Mode::Dedicated =>
            "# Dedicated: this box is a display. The unit takes tty1 from the\n\
             # getty and the greeter, so there is nothing behind the dashboard.\n",
        Mode::Shared =>
            "# Shared: this box is still a laptop. The desktop keeps tty1 and its\n\
             # greeter; the display lives on its own VT and you switch to it.\n\
             # Nothing here conflicts with the desktop, by design.\n",
    };
    format!(
        "# Written by `noo kiosk setup`.\n\
         {why}\
         [Unit]\n\
         Description=noomesh kiosk display (cage + chromium, {mode} on tty{vt})\n\
         After=systemd-user-sessions.service network-online.target plymouth-quit-wait.service kiosk-serve.service\n\
         Wants=network-online.target\n\
         Requires=kiosk-serve.service\n\
         {conflicts}\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         EnvironmentFile={env}\n\
         ExecStart={bin}/noo-kiosk-launch\n\
         Restart=always\n\
         RestartSec=5\n\
         PAMName=login\n\
         TTYPath=/dev/tty{vt}\n\
         TTYReset=yes\n\
         TTYVHangup=yes\n\
         StandardInput=tty\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         UtmpIdentifier=tty{vt}\n\
         UtmpMode=user\n\
         \n\
         [Install]\n\
         WantedBy=graphical.target\n",
        why = why, mode = mode.as_str(), vt = vt, conflicts = conflicts,
        user = user, env = ENV_FILE, bin = BIN_DIR,
    )
}

pub(crate) fn render_watchdog_service() -> String {
    format!(
        "# Written by `noo kiosk setup`. Root: it may restart kiosk.service.\n\
         [Unit]\n\
         Description=noomesh kiosk watchdog (token renewal, stale reload, dead-session restart)\n\
         After=kiosk.service\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         EnvironmentFile={env}\n\
         ExecStart={bin}/noo-kiosk-watchdog\n",
        env = ENV_FILE, bin = BIN_DIR,
    )
}

pub(crate) fn render_watchdog_timer() -> &'static str {
    "# Written by `noo kiosk setup`.\n\
     [Unit]\n\
     Description=noomesh kiosk watchdog, every minute\n\
     \n\
     [Timer]\n\
     OnBootSec=90s\n\
     OnUnitActiveSec=60s\n\
     AccuracySec=5s\n\
     \n\
     [Install]\n\
     WantedBy=timers.target\n"
}

/// The logind override. The lid and idle half applies to BOTH modes — a
/// display that sleeps when the lid closes or the room goes quiet is a
/// display that is off.
///
/// The VT half is dedicated-only, and it is the difference between a
/// dashboard and a dashboard with a login prompt one keystroke away.
/// `NAutoVTs` and `ReserveVT` default to 6, so logind spawns a getty ON
/// DEMAND when someone switches to an unused terminal. That is invisible
/// beforehand: `systemctl list-units 'getty@*'` shows only tty1, because
/// the others do not exist until the switch happens — a check that cannot
/// see the thing it is being used to rule out. Setting both to 0 stops the
/// spawning; masking `getty@.service` stops it being started by hand.
///
/// Shared mode must NOT do this: the laptop's own console logins are how
/// its owner gets in.
pub(crate) fn render_logind_conf(mode: Mode) -> String {
    let vts = match mode {
        Mode::Dedicated =>
            "\n\
             # Dedicated only. Both default to 6, so a plugged-in keyboard\n\
             # switching to an unused VT gets a login prompt spawned on demand.\n\
             # There is no console login behind the dashboard now — see the\n\
             # warning `noo kiosk setup` prints before masking the getty.\n\
             NAutoVTs=0\n\
             ReserveVT=0\n",
        Mode::Shared => "",
    };
    format!(
        "# Written by `noo kiosk setup` ({mode}). A display that sleeps when\n\
         # the lid is closed or the room is quiet is a display that is off.\n\
         [Login]\n\
         HandleLidSwitch=ignore\n\
         HandleLidSwitchExternalPower=ignore\n\
         HandleLidSwitchDocked=ignore\n\
         IdleAction=ignore\n\
         {vts}",
        mode = mode.as_str(), vts = vts,
    )
}

// ── host checks ────────────────────────────────────────────────────────

/// Does this setup disable the display manager? Only dedicated mode, and
/// only when it is enabled now.
fn display_manager_will_be_disabled(mode: Mode, is_enabled: Option<&str>) -> bool {
    mode == Mode::Dedicated && is_enabled == Some("enabled")
}

/// A yes/no that RETURNS rather than exiting, because declining to mask the
/// getty is a valid install and not an abort.
///
/// Fails toward leaving a way in: `--json`, a non-TTY, or an unreadable
/// answer all mean "no". The repo's `confirm_destructive` cannot be used
/// here — it exits the process on "no", which would abandon a half-written
/// seat, and it treats `--yes` as blanket consent, which for this
/// particular step is consent to lock yourself out of a machine.
fn ask_to_lock_out(g: &Globals, question: &str) -> bool {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    if g.json || !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn which(name: &str) -> Option<String> {
    let out = std::process::Command::new("bash").arg("-c").arg(format!("command -v {name}")).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() { None } else { Some(p) }
}

fn resolved(path: &str) -> String {
    std::fs::canonicalize(path).map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| path.to_string())
}

/// Which browser binary the seat runs, or why none will do.
///
/// Probes the Chromium family by name; `--browser` names one explicitly
/// (a name on PATH or a path). Google Chrome counts: same engine, same
/// flags, same CDP, and on Ubuntu it is the only non-snap option in a
/// .deb — Ubuntu's `chromium` package is a transitional stub for the snap.
const BROWSER_CANDIDATES: &[&str] = &["chromium", "chromium-browser", "google-chrome-stable", "google-chrome"];

const NO_BROWSER_HINT: &str = "Install a non-snap Chromium-family browser. Ubuntu: \
`wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
sudo apt install ./google-chrome-stable_current_amd64.deb` (then `noo kiosk setup` finds \
google-chrome-stable), or a PPA Chromium .deb. Debian: `sudo apt install chromium`. \
Name a binary or path with --browser.";

fn find_browser(explicit: Option<&str>) -> Result<String, String> {
    let names: Vec<&str> = match explicit {
        Some(b) => vec![b],
        None => BROWSER_CANDIDATES.to_vec(),
    };
    for name in names {
        let Some(p) = which(name) else { continue };
        let real = resolved(&p);
        if real.contains("/snap/") {
            return Err(format!(
                "{p} is the snap build ({real}). The snap relocates the profile and ~/.pki, \
                 so the seat's user-data-dir is not the one the browser runs with. {NO_BROWSER_HINT}"
            ));
        }
        return Ok(name.to_string());
    }
    match explicit {
        Some(b) => Err(format!("--browser {b}: not found on PATH. {NO_BROWSER_HINT}")),
        None => Err(format!("no Chromium-family browser found ({}). {NO_BROWSER_HINT}", BROWSER_CANDIDATES.join(", "))),
    }
}

fn sh(cmd: &str) -> Result<(), String> {
    let st = std::process::Command::new("bash").arg("-c").arg(cmd).status().map_err(|e| format!("{cmd}: {e}"))?;
    if st.success() { Ok(()) } else { Err(format!("`{cmd}` exited {st}")) }
}

fn sh_out(cmd: &str) -> Option<String> {
    let out = std::process::Command::new("bash").arg("-c").arg(cmd).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// stdout REGARDLESS of exit status; `None` only if the command could not
/// be run at all.
///
/// `systemctl is-enabled` uses its exit code as part of the answer: a
/// masked unit prints `masked` and exits **1**. Read through `sh_out`
/// that becomes `None`, and a status row built on it reported the
/// display's console logins as NOT masked while they were masked —
/// verified wrong on the live box, with the operator having watched setup
/// create the /dev/null symlink. A control reported OFF while it is ON is
/// worse than no row at all: it invites someone to "fix" what is not
/// broken.
fn sh_out_any(cmd: &str) -> Option<String> {
    let out = std::process::Command::new("bash").arg("-c").arg(cmd).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The "mint path" row, as a decision of its own so it can be TESTED
/// rather than grepped for.
///
/// THREE answers, not two. `via` is absent when token.json could not be
/// READ, which says nothing about which lane minted it — and that read
/// goes through `sudo -n`, so on the live box this same row answered
/// differently minutes apart, depending only on how recently a sudo
/// password had been typed. Reporting the retired key lane there sent an
/// operator with no stored key looking for one to revoke.
pub(crate) fn mint_path_row(via: Option<&str>) -> String {
    match via {
        Some("tailnet") => ui::good("tailnet (no stored secret)"),
        Some(other) => ui::warn(&format!(
            "{other} — a pre-keyless token; /etc/default/kiosk may still hold a key to revoke"
        )),
        None => ui::muted("unknown (the proxy has published no state)").to_string(),
    }
}

/// What `systemctl is-enabled getty@.service` says, as a tri-state.
///
/// `None` means we could not tell — which must NEVER be rendered as
/// "not masked". The three answers are different facts.
pub(crate) fn masked_from_is_enabled(out: Option<&str>) -> Option<bool> {
    match out.map(str::trim) {
        None | Some("") => None,
        Some("masked") | Some("masked-runtime") => Some(true),
        Some(_) => Some(false),
    }
}

/// `sudo install` the content, fed over a PIPE — it never becomes a file
/// anywhere but the destination, and never an argv word.
///
/// This used to stage through `/tmp/noo-kiosk-<pid>`, and one of these
/// files is the display's durable service key. Three things were wrong
/// with that, all of them only in the window before the file was moved:
///
/// - `fs::write` creates under the caller's UMASK, typically world-
///   readable, and the `set_permissions(0600)` came AFTER. Any local user
///   could read the key in between.
/// - the path is derived from the pid, so it is guessable rather than
///   random, which is what makes the window usable rather than theoretical.
/// - `fs::write` follows a symlink, so a pre-placed one at that guessable
///   path redirects the write — the key lands somewhere the attacker
///   chose, or truncates a file the caller can write.
///
/// `install -m` applies the mode at CREATION, so piping through
/// `/dev/stdin` closes all three: no intermediate file, no umask window,
/// nothing to pre-place. The content still never appears in argv, which
/// is why this is not `echo … | sudo tee`.
fn install_text(content: &str, dst: &str, mode: &str, owner: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};

    // bash -c because `owner` carries a shell fragment (`root -g kiosk`)
    // from the caller. The CONTENT never goes near the shell — it arrives
    // on stdin.
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(format!("sudo install -m {mode} -o {owner} -D /dev/stdin {dst}"))
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("install {dst}: {e}"))?;
    let mut sin = child
        .stdin
        .take()
        .ok_or_else(|| format!("install {dst}: no stdin"))?;
    crate::child_stdin::write_child_stdin(&mut sin, content.as_bytes()).map_err(|e| format!("install {dst}: {e}"))?;
    drop(sin);
    let st = child.wait().map_err(|e| format!("install {dst}: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("`sudo install … {dst}` exited {st}"))
    }
}

// ── setup ──────────────────────────────────────────────────────────────

/// `noo kiosk setup --mode dedicated|shared --url <ts.net url> [--user kiosk] [--view health|graph] [--rotate <secs>] [--dry-run]`
pub fn kiosk_setup(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = match parse_setup(args) {
        Ok(a) => a,
        Err(e) => fail(g.json, ExitCode::Usage, "usage", &e,
            Some("noo kiosk setup --mode dedicated|shared --url https://<controller>.<tailnet>.ts.net [--view health|graph]")),
    };
    if let Err(e) = validate_url(&a.url) {
        fail(g.json, ExitCode::Usage, "kiosk_url", &e, None);
    }

    let files: Vec<(String, String, &str, &str)> = vec![
        (ENV_FILE.into(), render_env(&a), "0640", "root"),
        (format!("{BIN_DIR}/noo-kiosk-launch"), LAUNCH.into(), "0755", "root"),
        (format!("{BIN_DIR}/noo-kiosk-cdp"), CDP.into(), "0755", "root"),
        (format!("{BIN_DIR}/noo-kiosk-watchdog"), WATCHDOG.into(), "0755", "root"),
        (format!("{BIN_DIR}/noo-kiosk-serve"), SERVE.into(), "0755", "root"),
        (format!("{UNIT_DIR}/kiosk-serve.service"), render_serve_service(&a.user), "0644", "root"),
        (format!("{UNIT_DIR}/kiosk.service"), render_kiosk_service(&a.user, a.mode, a.vt), "0644", "root"),
        (format!("{UNIT_DIR}/kiosk-watchdog.service"), render_watchdog_service(), "0644", "root"),
        (format!("{UNIT_DIR}/kiosk-watchdog.timer"), render_watchdog_timer().into(), "0644", "root"),
        (LOGIND_CONF.into(), render_logind_conf(a.mode), "0644", "root"),
    ];

    if a.dry_run {
        if g.json {
            let listing: Vec<_> = files.iter().map(|(p, c, m, o)| json!({"path": p, "mode": m, "owner": o, "content": c})).collect();
            println!("{}", json!({"dry_run": true, "user": a.user, "files": listing}));
            return Ok(0);
        }
        println!("{}", ui::header("kiosk setup", Some("dry run")));
        for (p, c, m, _) in &files {
            println!("{}", ui::section(&format!("{p}  ({m})")));
            // The key is the one secret in these files; a dry run prints
            // the rest so an operator can review it, and masks that.
            // Nothing rendered is a secret any more — the env file holds a
            // URL and a port — so a dry run prints it verbatim.
            let shown = c.clone();
            for line in shown.lines() {
                println!("  {line}");
            }
        }
        println!();
        ui::done("dry run: nothing written");
        return Ok(0);
    }

    if !cfg!(target_os = "linux") {
        fail(g.json, ExitCode::Generic, "platform", "noo kiosk setup is Linux-only (cage + systemd)", None);
    }
    if which("cage").is_none() {
        fail(g.json, ExitCode::Generic, "missing_cage",
            "cage (the kiosk compositor) is not installed",
            Some("sudo apt update && sudo apt install cage   # in universe on Ubuntu: `sudo add-apt-repository universe` first if it is not found"));
    }
    let browser = match find_browser(a.browser.as_deref()) {
        Ok(b) => b,
        Err(e) => fail(g.json, ExitCode::Generic, "missing_browser", &e, None),
    };
    if which("python3").is_none() {
        fail(g.json, ExitCode::Generic, "missing_python", "python3 is required by the CDP helper", Some("sudo apt install python3"));
    }

    // Dedicated mode turns the desktop login off. Ask BEFORE anything is
    // written, so declining leaves the box untouched.
    if display_manager_will_be_disabled(a.mode, sh_out("systemctl is-enabled display-manager.service 2>/dev/null").as_deref()) {
        super::confirm_destructive(
            g,
            a.yes,
            "disable the display manager (the desktop login) on",
            "this box; `noo kiosk teardown` re-enables it",
        );
    }

    println!("{}", ui::header("kiosk setup", Some(&a.url)));

    // 1. the user
    ui::step(&format!("ensuring user {}", a.user));
    if sh_out(&format!("id -u {}", a.user)).is_none() {
        if let Err(e) = sh(&format!(
            "sudo useradd --system --create-home --home-dir {STATE_DIR} --shell /usr/sbin/nologin \
             --groups video,input,render,audio {}", a.user)) {
            fail(g.json, ExitCode::Generic, "useradd", &e, None);
        }
        ui::done(&format!("created {} (system user, home {STATE_DIR})", a.user));
    } else {
        println!("{}", ui::note("exists; unchanged"));
    }
    // Two modes, deliberately. 0755 on the state dir because
    // `noo kiosk status` reads state.json there WITHOUT sudo, and a 0750
    // dir would make that file's 0644 meaningless to everyone outside the
    // kiosk group. Nothing in the dir is protected BY the dir: token.json
    // is 0600, and the browser profile — which holds the token at rest in
    // localStorage — is 0700 on its own.
    if let Err(e) = sh(&format!(
        "sudo install -d -m 0755 -o {u} -g {u} {STATE_DIR} && \
         sudo install -d -m 0700 -o {u} -g {u} {STATE_DIR}/profile",
        u = a.user
    )) {
        fail(g.json, ExitCode::Generic, "state_dir", &e, None);
    }

    // 2. the files
    for (p, c, m, o) in &files {
        ui::step(&format!("installing {p}"));
        // The env file is root:kiosk so the launcher (kiosk) can read it
        // and nothing else on the box can.
        let group = if p == ENV_FILE { a.user.as_str() } else { "root" };
        let mut content = c.clone();
        if p.ends_with("noo-kiosk-launch") && browser != "chromium" {
            content = content.replace("BROWSER=\"${NOO_KIOSK_BROWSER:-chromium}\"", &format!("BROWSER=\"${{NOO_KIOSK_BROWSER:-{browser}}}\""));
        }
        if let Err(e) = install_text(&content, p, m, &format!("{o} -g {group}")) {
            fail(g.json, ExitCode::Generic, "install", &e, None);
        }
    }

    // 3. What this mode is allowed to take away.
    //
    // Dedicated dismantles the machine's other ways in, on purpose. Shared
    // touches NONE of it: the desktop and the console logins are how the
    // laptop's owner uses their laptop.
    if a.mode == Mode::Dedicated {
        // A display manager would put a greeter on tty1 — a lock screen the
        // display can never get past — and its desktop session would
        // idle-lock over the top of cage. The unit Conflicts= it; disabling
        // it here stops a reboot racing the two for the seat.
        if sh_out("systemctl is-enabled display-manager.service 2>/dev/null").as_deref() == Some("enabled") {
            ui::step("disabling the display manager (a greeter on tty1 would be a lock screen)");
            if let Err(e) = sh("sudo systemctl disable --now display-manager.service") {
                ui::warned(&format!("{e} — the kiosk unit still Conflicts= it, but disable it before rebooting"));
            }
        }
        // Masking the getty is the one step that can lock a person out of
        // their own machine, so it ASKS. The logind override above already
        // stops VTs autospawning; the mask stops one being started by hand.
        println!();
        println!("{}", ui::warn("Dedicated mode removes every console login on this box."));
        println!("{}", ui::note(
            "NAutoVTs=0 and ReserveVT=0 stop a login prompt appearing when someone switches \
             terminals — that is the point. But if kiosk.service then fails to start, there is \
             NO console to log in on. On a machine without SSH that is a lockout, recoverable \
             only from the installer or single-user mode.",
        ));
        if ask_to_lock_out(g, &format!(
            "mask getty@.service on this box? (SSH is your way back in; `noo kiosk teardown` unmasks it){}",
            if sh_out("systemctl is-active ssh.service sshd.service 2>/dev/null").is_some() { "" } else { " — WARNING: no sshd appears to be running here" },
        )) {
            ui::step("masking getty@.service");
            if let Err(e) = sh("sudo systemctl mask getty@.service") {
                ui::warned(&format!("{e} — VTs still do not autospawn, but a getty can be started by hand"));
            }
        } else {
            println!("{}", ui::note(
                "left unmasked. NAutoVTs=0 still stops the automatic prompt; someone with root \
                 could start a getty deliberately.",
            ));
        }
    } else {
        println!();
        println!("{}", ui::note(&format!(
            "Shared mode: the desktop, its greeter and the console logins are untouched. The \
             display runs on tty{vt} — switch with Ctrl+Alt+F{vt}, and back the same way.",
            vt = a.vt,
        )));
        println!("{}", ui::note(
            "What this does NOT protect: the dashboard is only unattended while its VT is the \
             active one, and what protects the desktop behind it is the desktop's own lock, not \
             anything installed here.",
        ));
    }
    ui::step("enabling units");
    for cmd in [
        "sudo systemctl daemon-reload",
        // The proxy first, and restarted rather than started: on a re-run
        // the old one is still holding the port with the old code.
        "sudo systemctl enable kiosk-serve.service",
        "sudo systemctl restart kiosk-serve.service",
        "sudo systemctl enable kiosk-watchdog.timer",
        "sudo systemctl enable kiosk.service",
        "sudo systemctl restart kiosk.service",
        "sudo systemctl start kiosk-watchdog.timer",
    ] {
        if let Err(e) = sh(cmd) {
            fail(g.json, ExitCode::Generic, "systemctl", &e, Some("journalctl -u kiosk.service -n 50"));
        }
    }
    // A display is a viewer, not an enrolled node: no noo-hostd runs here, so
    // nothing reports its tailscaled to `noo cluster verify`. Setup is the one
    // moment noomesh configures this host, so it sets the switch itself.
    ui::step("tailscaled log upload");
    match sh(&tailscale_logs_off_cmd()) {
        Ok(()) => ui::done("tailscaled does not upload its client logs to Tailscale (or tailscale is not installed here, or /etc/noo/allow-tailscale-log-upload opts in)"),
        Err(e) => ui::warned(&format!("could not switch off tailscaled's log upload: {e} — `noo kiosk status` shows where it stands")),
    }
    println!();
    // The browser is pointed at the LOCAL proxy, which forwards to the
    // controller. Printing the controller URL here claimed a page the
    // browser never loads directly.
    ui::done(&format!(
        "kiosk seat installed; the browser shows http://127.0.0.1:8088/kiosk.html?view={} via the local proxy, upstream {}",
        a.view, a.url
    ));
    ui::guide(&[
        ("noo kiosk status", "units, CDP, token expiry and the page's heartbeat"),
        ("journalctl -u kiosk.service -f", "the launcher's own account of the session"),
        ("sudo systemctl restart systemd-logind", "applies the lid/idle overrides now (or reboot)"),
    ]);
    Ok(0)
}

// ── host telemetry (docs/security/telemetry.md, "Host software") ───────

/// The shell the seat runs to switch off tailscaled's client-log upload: the
/// same script `noo enroll` uses (switch in `/etc/default/tailscaled`, restart
/// only if it was added, nothing at all where the operator's opt-in marker
/// exists), skipped where tailscaled is not installed.
pub(crate) fn tailscale_logs_off_cmd() -> String {
    format!("command -v tailscaled >/dev/null 2>&1 || exit 0; {}", crate::vendor::tailscale_nologs_linux_script())
}

/// Does `/etc/default/tailscaled` carry the switch on a live (uncommented) line?
pub(crate) fn defaults_have_switch(defaults: &str) -> bool {
    defaults.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| {
        l.contains("no-logs-no-support")
            || l.contains(&format!("{}=true", crate::vendor::TAILSCALE_NO_LOGS_ENV))
            || l.contains(&format!("{}=1", crate::vendor::TAILSCALE_NO_LOGS_ENV))
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TsLogs {
    /// tailscaled is not installed on this box.
    NotInstalled,
    /// The operator allowed the upload (the marker file) and it is on.
    OperatorChoice,
    /// The switch is on the running process or in a file the process started after.
    Off,
    /// The file has the switch but the running tailscaled started before it.
    OffAfterRestart,
    /// tailscaled is not running; the file decides its next start.
    NotRunning { configured: bool },
    /// Uploading.
    On,
}

/// What an UNPRIVILEGED `noo kiosk status` can prove (a root process's
/// environment is unreadable, so a file-configured switch is judged by whether
/// the process started after the file was last written).
/// `cmdline` is the running tailscaled's arguments, `None` when it is not running.
pub(crate) fn tailscale_logs_state(
    installed: bool,
    marker: bool,
    defaults: Option<&str>,
    cmdline: Option<&str>,
    process_started_after_file: Option<bool>,
) -> TsLogs {
    if !installed {
        return TsLogs::NotInstalled;
    }
    let in_file = defaults.is_some_and(defaults_have_switch);
    let on_cmdline = cmdline.is_some_and(|c| c.contains("no-logs-no-support"));
    let Some(_) = cmdline else { return TsLogs::NotRunning { configured: in_file } };
    if on_cmdline {
        return TsLogs::Off;
    }
    if in_file {
        return if process_started_after_file == Some(false) { TsLogs::OffAfterRestart } else { TsLogs::Off };
    }
    if marker { TsLogs::OperatorChoice } else { TsLogs::On }
}

/// Ubuntu's reporters that can be on at a display: the same three
/// noo-hostd reports on a node. (Raspberry Pi OS ships none of them; see the doc.)
pub(crate) fn os_reporters(motd_news_enabled: bool, popcon_conf: Option<&str>, whoopsie_active: bool) -> Vec<&'static str> {
    let mut v = Vec::new();
    if motd_news_enabled { v.push("motd-news"); }
    if popcon_conf.is_some_and(|c| c.lines().any(|l| l.trim().replace(' ', "") == "PARTICIPATE=\"yes\"")) { v.push("popularity-contest"); }
    if whoopsie_active { v.push("whoopsie"); }
    v
}

/// Process start (unix secs) from `/proc/<pid>/stat` text and the boot time.
/// Field 22 is the start in clock ticks after boot; the command name (field 2)
/// may hold spaces and parentheses, so fields count from the LAST `)`.
pub(crate) fn process_start_unix(stat: &str, boot_unix: i64, clk_tck: i64) -> Option<i64> {
    let after = &stat[stat.rfind(')')? + 1..];
    let ticks: i64 = after.split_whitespace().nth(19)?.parse().ok()?;
    (clk_tck > 0).then(|| boot_unix + ticks / clk_tck)
}

fn telemetry_rows_cell(rows: &[(&'static str, String)], key: &str) -> String {
    rows.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone()).unwrap_or_default()
}

/// The two `noo kiosk status` rows for the host's own reporters, read without privilege.
fn telemetry_rows() -> Vec<(&'static str, String)> {
    let defaults = std::fs::read_to_string("/etc/default/tailscaled").ok();
    let pid = sh_out("pidof tailscaled").and_then(|p| p.split_whitespace().next().map(str::to_string));
    let cmdline = pid.as_ref().and_then(|p| std::fs::read(format!("/proc/{p}/cmdline")).ok())
        .map(|b| String::from_utf8_lossy(&b).replace('\0', " "));
    let started_after = (|| {
        let pid = pid.as_ref()?;
        let file_mtime = std::fs::metadata("/etc/default/tailscaled").ok()?.modified().ok()?
            .duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
        let btime: i64 = std::fs::read_to_string("/proc/stat").ok()?.lines()
            .find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())?;
        let tck: i64 = sh_out("getconf CLK_TCK")?.parse().ok()?;
        let start = process_start_unix(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?, btime, tck)?;
        Some(start >= file_mtime)
    })();
    let marker = std::path::Path::new(crate::vendor::TAILSCALE_UPLOAD_MARKER).exists();
    let ts = match tailscale_logs_state(which("tailscaled").is_some(), marker, defaults.as_deref(), cmdline.as_deref(), started_after) {
        TsLogs::NotInstalled => ui::muted("tailscaled not installed").to_string(),
        TsLogs::Off => ui::good("off (the switch is on)"),
        TsLogs::NotRunning { configured: true } => ui::good("off (tailscaled not running; the switch is in /etc/default/tailscaled)"),
        TsLogs::NotRunning { configured: false } => ui::warn("tailscaled not running and the switch is not set — `noo kiosk setup` sets it"),
        TsLogs::OffAfterRestart => ui::warn("set in /etc/default/tailscaled but the running tailscaled predates it — `sudo systemctl restart tailscaled`"),
        TsLogs::OperatorChoice => ui::warn(&format!("uploads, by operator choice ({} exists)", crate::vendor::TAILSCALE_UPLOAD_MARKER)),
        TsLogs::On => ui::bad("tailscaled uploads its client logs to Tailscale — `noo kiosk setup` switches it off"),
    };
    let motd = sh_out_any("systemctl is-enabled motd-news.timer 2>/dev/null").as_deref() == Some("enabled");
    let whoopsie = sh_out_any("systemctl is-active whoopsie 2>/dev/null").as_deref() == Some("active");
    let popcon = std::fs::read_to_string("/etc/popularity-contest.conf").ok();
    let rep = os_reporters(motd, popcon.as_deref(), whoopsie);
    let reporters = if rep.is_empty() {
        ui::good("none enabled")
    } else {
        ui::warn(&format!("{} enabled (Ubuntu's own; docs/security/telemetry.md has the command to turn each off)", rep.join(", ")))
    };
    vec![("tailscale logs", ts), ("os reporters", reporters)]
}

// ── serve ──────────────────────────────────────────────────────────────

/// `noo kiosk serve [--port N]` — the local proxy, in the foreground.
///
/// Normally `kiosk-serve.service` runs this and you never type it. It is a
/// verb because the page names it (`ui/apps/web/src/kiosk/main.tsx`), and
/// because running it by hand is how you find out why a display has no
/// credential without reading a unit file to guess the arguments.
///
/// Execs the installed asset rather than reimplementing it, so what you
/// debug here is byte-for-byte what the unit runs.
pub fn kiosk_serve(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut port: Option<String> = None;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "--port" => port = Some(it.next().ok_or(Unhandled)?.clone()),
            _ => return Err(Unhandled),
        }
    }
    let bin = format!("{BIN_DIR}/noo-kiosk-serve");
    if !std::path::Path::new(&bin).exists() {
        fail(g.json, ExitCode::Generic, "not_installed",
            &format!("{bin} is not installed on this box"),
            Some("noo kiosk setup --mode dedicated|shared --url https://<controller>.<tailnet>.ts.net"));
    }
    let mut cmd = std::process::Command::new(&bin);
    if let Some(p) = &port {
        cmd.arg("--port").arg(p);
    }
    match cmd.status() {
        Ok(st) => Ok(st.code().unwrap_or(1)),
        Err(e) => fail(g.json, ExitCode::Generic, "spawn", &format!("{bin}: {e}"), None),
    }
}

// ── status ─────────────────────────────────────────────────────────────

/// `noo kiosk status`
/// `noo kiosk reload` — reload the page on the screen.
///
/// The seat installs `noo-kiosk-cdp`, and reloading the display meant
/// knowing that, which is an implementation detail the operator should
/// never have had to learn. `noo` is the front door.
///
/// It also answers the question the reload is usually FOR. A console
/// change reaches this screen when the controller rolls a new stack tag,
/// not when this machine upgrades — so the operator reloads and then
/// wonders whether anything actually changed. This reports the build
/// either side of the reload, so "did the roll take?" is answered by the
/// same command that did it.
/// The scripts `setup` installs, beside the copy this binary carries.
const SEAT_ASSETS: &[(&str, &str)] = &[
    ("/usr/local/bin/noo-kiosk-launch", LAUNCH),
    ("/usr/local/bin/noo-kiosk-cdp", CDP),
    ("/usr/local/bin/noo-kiosk-watchdog", WATCHDOG),
    ("/usr/local/bin/noo-kiosk-serve", SERVE),
];

/// `setup` rewrites this one line per box, so it is not evidence of age.
fn without_local_edits(s: &str) -> String {
    s.lines().filter(|l| !l.trim_start().starts_with("BROWSER=")).collect::<Vec<_>>().join("\n")
}

/// Installed seat scripts that differ from the ones this `noo` carries.
///
/// `noo upgrade` replaces the BINARY and nothing else. These four live in
/// /usr/local/bin, put there by `setup`, so an upgrade leaves a display
/// running the previous release's proxy, launcher and watchdog — and the
/// only symptom is a feature that silently does not exist.
///
/// That is not hypothetical. `status` asked the installed `noo-kiosk-cdp`
/// for the console build, got `unknown subcommand 'build'`, read the
/// failure as "the page did not say", and reported a CURRENT console as
/// one predating the build stamp. Two causes, one answer, and it blamed
/// the wrong machine.
///
/// Empty when no seat is installed here: a controller is not a stale
/// display.
fn stale_seat_assets() -> Vec<&'static str> {
    let present = SEAT_ASSETS.iter().filter(|(p, _)| std::path::Path::new(p).exists()).count();
    if present == 0 {
        return Vec::new();
    }
    SEAT_ASSETS
        .iter()
        .filter(|(path, embedded)| match std::fs::read_to_string(path) {
            Ok(disk) => without_local_edits(&disk) != without_local_edits(embedded),
            // Missing while its siblings are here: setup ran, then this one
            // was removed or never written. Stale either way.
            Err(_) => true,
        })
        .map(|(path, _)| path.rsplit('/').next().unwrap_or(path))
        .collect()
}

/// The `console build` cell.
///
/// Kept separate from the probing so the four cases can be held to
/// account: a build, a console too old to state one, a helper too old to
/// ask, and no browser at all. The third used to be reported as the
/// second.
fn console_build_row(build: Option<&str>, cdp_answering: bool, cdp_stale: bool) -> String {
    match build {
        Some(b) => b.to_string(),
        None if !cdp_answering => ui::muted("unknown (CDP not answering)").to_string(),
        None if cdp_stale => ui::warn(
            "cannot ask — the installed noo-kiosk-cdp predates this noo; run `noo kiosk setup`",
        ),
        None => ui::muted("not stated (a console from before stack-v0.2.59)").to_string(),
    }
}

pub fn kiosk_reload(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    if sh_out("noo-kiosk-cdp probe 2>/dev/null").is_none() {
        fail(
            g.json,
            ExitCode::Generic,
            "cdp",
            "the browser is not answering on the debug port, so there is nothing to reload",
            Some("noo kiosk status"),
        );
    }
    let build = || sh_out("noo-kiosk-cdp build 2>/dev/null").filter(|b| !b.is_empty() && b != "null");
    let before = build();

    if !g.json {
        ui::step("reloading the display");
    }
    if let Err(e) = sh("noo-kiosk-cdp reload") {
        fail(g.json, ExitCode::Generic, "cdp", &e, Some("journalctl -u kiosk.service -n 50"));
    }

    // The page needs a moment to come back before it can state anything.
    // Poll rather than sleep a fixed time: on a slow display the fixed
    // sleep is either a lie or a wait nobody needed.
    let mut after = None;
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        after = build();
        if after.is_some() {
            break;
        }
    }

    if g.json {
        println!(
            "{}",
            json!({ "reloaded": true, "console_build_before": before, "console_build_after": after })
        );
        return Ok(0);
    }
    ui::done("reloaded");
    let line = match (&before, &after) {
        (Some(b), Some(a)) if b == a => format!("console build {a} (unchanged)"),
        (_, Some(a)) => match &before {
            Some(b) => format!("console build {b} -> {a}"),
            None => format!("console build {a}"),
        },
        // Pre-stamp consoles say nothing, and so should this rather than
        // implying the reload failed.
        (_, None) => "console build not stated (a console from before stack-v0.2.59)".to_string(),
    };
    println!("{}", ui::note(&line));
    Ok(0)
}

pub fn kiosk_status(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let unit = |u: &str| sh_out(&format!("systemctl is-active {u}")).unwrap_or_else(|| "inactive".into());
    let kiosk = unit("kiosk.service");
    let proxy = unit("kiosk-serve.service");
    let timer = unit("kiosk-watchdog.timer");
    let cdp = sh_out("noo-kiosk-cdp probe 2>/dev/null").is_some();

    // EVERYTHING BELOW IS READ WITHOUT PRIVILEGE, on purpose.
    //
    // This ran as the operator and answered `Mode unknown (try sudo)` and
    // `Mint Path: key (pre-keyless — check for a stored key)` on an
    // install that has no key at all. It could not read the root-owned
    // files, so it GUESSED — and guessed a security-relevant fact
    // backwards. A status command that needs a password gets run less
    // often, and this is a display nobody is watching.
    //
    // So the proxy publishes what it knows to state.json (0644, no
    // secret in it) and this reads that. token.json stays 0600 and is
    // NOT read here — `status_reads_no_secret` guards that, because the
    // easy regression is to start reading it again as a "fallback".
    let state = std::fs::read_to_string(format!("{STATE_DIR}/state.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let s_str = |k: &str| -> Option<String> {
        state.as_ref().and_then(|v| v[k].as_str()).map(str::to_string)
    };
    let s_i64 = |k: &str| -> Option<i64> { state.as_ref().and_then(|v| v[k].as_i64()) };

    // No `.or_else(|| read(token.json))`. That fallback was in the first
    // draft of this and it is exactly the regression the guard below
    // exists to catch: it would work as root, do nothing as the operator,
    // and quietly reintroduce a privileged read into a command whose
    // whole point is that it needs none.
    let expires = s_i64("expires_at");
    let minted_at = s_i64("minted_at");
    let published_at = s_i64("updated_at");
    let via = s_str("mint");
    let last_error = s_str("last_error");
    let last_error_at = s_i64("last_error_at");
    let mode = s_str("mode");
    let vt = s_str("vt");
    let view = s_str("view");
    // The port the proxy says it bound, not the one we would have chosen:
    // `--port` makes those different and the browser follows the former.
    let port = s_i64("port").unwrap_or(PROXY_PORT as i64);

    // "Active" is not "listening" — the unit can be up with the socket
    // unbound, and the browser only cares about the socket. Connecting is
    // the honest test and needs no privilege.
    let proxy_listening = sh_out(&format!(
        "(exec 3<>/dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo yes"
    ))
    .as_deref()
        == Some("yes");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let heartbeat = if cdp { sh_out("noo-kiosk-cdp heartbeat 2>/dev/null").and_then(|s| s.parse::<i64>().ok()) } else { None };
    // The graph's own measure of how slow the box is: smoothed ms of work
    // per frame and the tier it chose. "Choppy" was the operator's word;
    // this is the number behind it, so the next conversation starts there.
    // Which build of the console is actually on the screen. Two sessions
    // once spent an evening unable to answer this from anything but tag
    // ancestry, because everything greppable in the bundle had been
    // renamed by the minifier.
    let stale = stale_seat_assets();
    let console_build = if cdp {
        sh_out("noo-kiosk-cdp build 2>/dev/null").filter(|s| !s.is_empty() && s != "null")
    } else {
        None
    };
    let frame = if cdp {
        sh_out("noo-kiosk-cdp frame 2>/dev/null").and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()).filter(|v| v.is_object())
    } else {
        None
    };
    // `sh_out_any`, not `sh_out`: `is-enabled` exits 1 for a masked unit
    // while printing the answer. See `masked_from_is_enabled`.
    let getty_masked = masked_from_is_enabled(
        sh_out_any("systemctl is-enabled getty@.service 2>/dev/null").as_deref(),
    );
    // Whether the controller is sending this display entity names — asked
    // through the proxy, which holds the credential so this does not.
    let labels = if proxy_listening { labels_via_proxy(port) } else { None };

    if g.json {
        println!("{}", json!({
            "kiosk_service": kiosk, "watchdog_timer": timer, "cdp": cdp,
            "proxy_service": proxy, "proxy_listening": proxy_listening, "proxy_port": port,
            "token_expires_at": expires, "heartbeat_ms": heartbeat, "graph_frame": frame,
            "console_build": console_build, "stale_seat_assets": stale,
            "mint": via, "minted_at": minted_at,
            "last_error": last_error, "last_error_at": last_error_at,
            "state_published_at": published_at,
            "mode": mode, "vt": vt, "view": view, "getty_masked": getty_masked,
            "graph_labels": labels,
        }));
        return Ok(0);
    }
    println!("{}", ui::header("kiosk", None));
    // "The proxy has not said" is a real answer and a different one from
    // "expired". Neither is a guess.
    let unsaid = ui::muted("unknown (the proxy has published no state)").to_string();
    let expiry = match expires {
        Some(e) if e > now => format!("in {}s", e - now),
        Some(_) => ui::bad("expired"),
        None => unsaid.clone(),
    };
    let hb = match heartbeat {
        Some(ms) => {
            let age = (now * 1000 - ms) / 1000;
            if age > 300 { ui::warn(&format!("{age}s ago (stale)")) } else { ui::good(&format!("{age}s ago")) }
        }
        None if cdp => ui::muted("none yet (page has not received data)"),
        None => ui::muted("unknown (CDP not answering)"),
    };
    let mode_cell = match (mode.as_deref(), vt.as_deref()) {
        (Some("shared"), Some(v)) => format!("shared (tty{v} — Ctrl+Alt+F{v}; desktop untouched)"),
        (Some("dedicated"), _) => format!(
            "dedicated (tty1; console logins {})",
            match getty_masked {
                Some(true) => "masked".to_string(),
                Some(false) => ui::warn("NOT masked"),
                // Never claim a control is off because we could not read it.
                // `is-enabled` needs no privilege, so "try sudo" was
                // advice that could not work. Silence here means
                // systemctl did not answer at all.
                None => ui::muted("mask state unknown (systemctl did not answer)").to_string(),
            },
        ),
        (Some(m), _) => m.to_string(),
        (None, _) => unsaid.clone(),
    };
    let telem = telemetry_rows();
    println!("{}", ui::kv(&[
        ("kiosk.service", ui::state(&kiosk)),
        ("mode", mode_cell),
        // Which screen is actually up. The operator asked "why is the
        // graph not showing" about a seat installed with the default
        // health view, and nothing here could answer it.
        ("view", view.clone().map(|v| v.to_string()).unwrap_or_else(|| unsaid.clone())),
        ("graph labels", seat_labels_cell(labels, proxy_listening)),
        ("local proxy", if proxy_listening {
            ui::good(&format!("listening on 127.0.0.1:{port}"))
        } else if proxy == "active" {
            ui::bad(&format!("active but NOT listening on {port}"))
        } else {
            ui::bad(&format!("{proxy} — the browser has nothing to talk to"))
        }),
        ("watchdog timer", ui::state(&timer)),
        ("browser (CDP :9222)", if cdp { ui::good("answering") } else { ui::bad("not answering") }),
        ("mint path", mint_path_row(via.as_deref())),
        ("last mint", match minted_at {
            Some(m) if m <= now => format!("{}s ago", now - m),
            // A restarted proxy reuses the still-valid token it left on
            // disk and mints nothing until that nears expiry — up to
            // thirteen minutes of "no mint yet" on a seat that is fine.
            // The state IS published in that window; saying otherwise
            // named the wrong cause and sent the operator looking at a
            // proxy that had nothing wrong with it.
            None if state.is_some() => ui::muted("none since the proxy started (a still-valid token was carried over)").to_string(),
            _ => unsaid.clone(),
        }),
        ("token expires", expiry),
        ("page heartbeat", hb),
        ("console build", console_build_row(console_build.as_deref(), cdp, stale.contains(&"noo-kiosk-cdp"))),
        // `noo upgrade` does not touch these; only `setup` installs them.
        ("seat assets", if stale.is_empty() {
            ui::good("match this noo")
        } else {
            ui::warn(&format!("stale: {} — run `noo kiosk setup`", stale.join(", ")))
        }),
        ("tailscale logs", telemetry_rows_cell(&telem, "tailscale logs")),
        ("os reporters", telemetry_rows_cell(&telem, "os reporters")),
        ("graph frame", match &frame {
            Some(v) => {
                let ms = v["ms"].as_i64().unwrap_or(0);
                let tier = v["quality"].as_str().unwrap_or("?");
                let s = format!("{ms}ms of work per frame, drawing {tier}");
                if ms > 33 { ui::warn(&s) } else { s }
            }
            None if cdp => ui::muted("not measured (not the graph view, or the page has not painted yet)").to_string(),
            None => ui::muted("unknown (CDP not answering)").to_string(),
        }),
        ("last error", match (&last_error, last_error_at) {
            (Some(e), Some(t)) if t <= now => ui::warn(&format!("{} ({}s ago)", e.trim(), now - t)),
            (Some(e), _) => ui::warn(e.trim()),
            (None, _) if state.is_some() => ui::good("none"),
            (None, _) => unsaid.clone(),
        }),
        ("state published", match published_at {
            Some(t) if now - t > 120 => ui::warn(&format!("{}s ago (stale — is the proxy running?)", now - t)),
            Some(t) => format!("{}s ago", now - t),
            None => unsaid.clone(),
        }),
    ]));
    if kiosk != "active" {
        ui::guide(&[("journalctl -u kiosk.service -n 50", "why the session is not up")]);
    }
    if !proxy_listening {
        ui::guide(&[(
            "journalctl -u kiosk-serve.service -n 50",
            "the proxy holds the credential; nothing loads without it",
        )]);
    }
    Ok(0)
}

// ── teardown ───────────────────────────────────────────────────────────

// ── invite (controller side) ───────────────────────────────────────────

pub(crate) const KIOSK_TAG: &str = "tag:kiosk";
pub(crate) const CONTROLLER_TAG: &str = "tag:controller";
const SERVE_PORT: u16 = 443;

#[derive(Debug, PartialEq)]
pub(crate) struct InviteArgs {
    pub name: String,
    pub expiry_minutes: i64,
    pub url: Option<String>,
}

pub(crate) fn parse_invite(args: &[String]) -> Result<InviteArgs, String> {
    let mut name: Option<String> = None;
    let mut expiry_minutes: i64 = 60;
    let mut url: Option<String> = None;
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            // Capped the service key's request rate. There is no service
            // key now, so this would silently do nothing — refuse instead.
            "--rpm" => {
                return Err(
                    "--rpm is retired: it capped the kiosk service key's request rate, and the \
                     display no longer holds one. Its token is minted per-renewal by tailnet \
                     proof and the mint route is rate-limited on the gateway."
                        .into(),
                )
            }
            "--expiry-minutes" => {
                expiry_minutes = it.next().and_then(|v| v.parse().ok()).ok_or("--expiry-minutes needs a number")?
            }
            "--url" => url = Some(it.next().ok_or("--url needs a value")?.trim_end_matches('/').to_string()),
            s if !s.starts_with('-') && name.is_none() => name = Some(s.to_string()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let name = name.ok_or("usage: noo kiosk invite <display-name> [--expiry-minutes <n>] [--url <https://…ts.net>]")?;
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("display name must be [A-Za-z0-9_-] (it names the tailnet device)".into());
    }
    Ok(InviteArgs { name, expiry_minutes, url })
}

/// The controller's serve URL: `NOO_KIOSK_URL` / `--url` when the operator
/// says so, else derived from this machine's tailnet DNS name.
fn serve_url(explicit: Option<&str>) -> Option<String> {
    if let Some(u) = explicit {
        return Some(u.to_string());
    }
    let env = std::env::var("NOO_KIOSK_URL").unwrap_or_default();
    if !env.trim().is_empty() {
        return Some(env.trim().trim_end_matches('/').to_string());
    }
    let out = std::process::Command::new("tailscale").args(["status", "--json"]).output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let dns = v["Self"]["DNSName"].as_str()?.trim_end_matches('.');
    if dns.is_empty() { None } else { Some(format!("https://{dns}")) }
}

/// `noo kiosk invite <name> [--expiry-minutes <n>] [--url <u>]` —
/// run on the CONTROLLER. Everything the display needs, minted here so the
/// operator never edits the tailnet policy by hand (the same lane
/// `cluster invite` uses for workers):
///
/// 1. `tag:kiosk` declared in `tagOwners` (admin + tag:controller as
///    co-owner, so the OAuth client can mint for it — finding #46);
/// 2. an ACL rule `tag:kiosk → tag:controller:443` — the serve port and
///    nothing else; a display never needs 8080;
/// 3. a single-use, pre-authorized tailnet auth key carrying `tag:kiosk`;
/// 4. the two commands to paste on the laptop.
///
/// It issues NO service key: the display authenticates by BEING the
/// tagged tailnet device, a fact the controller re-verifies at every
/// mint rather than a secret the display keeps.
///
/// **Steps 1–2 are a convergence, not the declaration.** `config/tailscale-acl.hujson`
/// is the tailnet policy this project DECLARES, and `noo security tailnet
/// policy --push` pushes it WHOLESALE — it replaces the live policy rather
/// than merging into it. So anything this function adds over the API and the
/// declaration does not carry is deleted the next time the policy is pushed, silently,
/// and every tagged display goes dark while `tailscale ping` still succeeds.
/// `tag:kiosk` and its `:443` rule are therefore in that file, and
/// `the_declared_acl_carries_the_kiosk_grant` fails if they leave it. What
/// this function is for is the tailnet that has not been re-pushed since —
/// including, when this shipped, the live one.
///
/// Nothing here touches the laptop. Re-running is safe: steps 1–2 are
/// idempotent, 3 mints a fresh auth key (revoke the old service key with
/// `noo security service-key revoke kiosk-<name>` if it was ever used).
pub fn kiosk_invite(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let a = match parse_invite(args) {
        Ok(a) => a,
        Err(e) => fail(g.json, ExitCode::Usage, "usage", &e, None),
    };
    use super::cluster_provision::{ensure_acl_grant, ensure_tag_owner, mint_tagged_auth_key, AclRuleOutcome, TagOwnerOutcome};

    if !g.json {
        println!("{}", ui::header("kiosk invite", Some(&a.name)));
    }

    // 1. tagOwners
    ui::step(&format!("declaring {KIOSK_TAG} in the tailnet policy"));
    match ensure_tag_owner(KIOSK_TAG) {
        Ok(TagOwnerOutcome::AlreadyPresent) => println!("{}", ui::note("already declared")),
        Ok(TagOwnerOutcome::Added) => ui::done(&format!("{KIOSK_TAG} added to tagOwners (owners: autogroup:admin, {CONTROLLER_TAG})")),
        Err(e) => fail(g.json, ExitCode::Generic, "tailnet_policy", &e, None),
    }

    // 2. BOTH rules. Outbound is how the display reads the page; inbound
    // on the dialback port is how it proves who it is without holding a
    // secret. Neither alone is enough.
    ui::step(&format!("granting {KIOSK_TAG} → {CONTROLLER_TAG}:{SERVE_PORT}"));
    match ensure_acl_grant(KIOSK_TAG, CONTROLLER_TAG, SERVE_PORT) {
        Ok(AclRuleOutcome::AlreadyPresent) => println!("{}", ui::note("rule already present")),
        Ok(AclRuleOutcome::Added) => ui::done("rule added"),
        Err(e) => fail(g.json, ExitCode::Generic, "tailnet_policy", &e, None),
    }
    ui::step(&format!("granting {CONTROLLER_TAG} → {KIOSK_TAG}:{DIALBACK_PORT} (dialback)"));
    match ensure_acl_grant(CONTROLLER_TAG, KIOSK_TAG, DIALBACK_PORT) {
        Ok(AclRuleOutcome::AlreadyPresent) => println!("{}", ui::note("rule already present")),
        Ok(AclRuleOutcome::Added) => ui::done("rule added"),
        Err(e) => fail(g.json, ExitCode::Generic, "tailnet_policy", &e, None),
    }

    // 3. tagged auth key — the ONLY thing this prints that is a secret,
    // and it is single-use and short-lived.
    ui::step("minting a single-use tailnet auth key");
    let auth_key = match mint_tagged_auth_key(KIOSK_TAG, a.expiry_minutes * 60, &format!("noo-kiosk-{}", a.name)) {
        Ok(k) => k,
        Err(e) => fail(g.json, ExitCode::Generic, "tailscale_error", &e, None),
    };
    ui::done(&format!("auth key minted ({KIOSK_TAG}, single-use, expires in {} min)", a.expiry_minutes));

    // No service key is issued. The display authenticates by BEING the
    // tagged tailnet device, which is a fact the controller verifies at
    // every mint rather than a secret the display keeps.

    let url = serve_url(a.url.as_deref());
    if g.json {
        println!("{}", json!({
            "tag": KIOSK_TAG, "auth_key": auth_key, "url": url,
            "expiry_minutes": a.expiry_minutes, "mint": "tailnet",
            "dialback_port": DIALBACK_PORT,
        }));
        return Ok(0);
    }

    println!();
    println!("{}", ui::section("on the display (paste in order; the auth key is shown once)"));
    println!("  sudo tailscale up --auth-key={auth_key} --force-reauth");
    match &url {
        Some(u) => println!("  noo kiosk setup --url {u} --view health"),
        None => println!("  noo kiosk setup --url https://<controller>.<tailnet>.ts.net --view health"),
    }
    println!();
    println!("{}", ui::note(
        "no service key: the display stores nothing durable. It mints a 15-minute token by \
         proving its tailnet identity, so revoking the tailnet device is what revokes the display.",
    ));
    if url.is_none() {
        println!("{}", ui::note("could not derive this controller's ts.net name; pass --url or set NOO_KIOSK_URL"));
    }
    ui::guide(&[
        ("noo kiosk status", "on the display, after setup: units, CDP, token expiry, heartbeat"),
        ("tailscale admin console", "remove the display's device — with no stored secret, that is the revocation"),
    ]);
    Ok(0)
}

// ── labels (controller side) ───────────────────────────────────────────

/// The controller setting that decides whether the kiosk display is sent
/// entity names. Registered in `gateway-rust/src/routes/settings.rs`
/// (`KIOSK_GRAPH_LABELS`), read by `routes/kiosk.rs::graph_labels_on`.
pub(crate) const LABELS_SETTING: &str = "kiosk.graph_labels";

/// The switch as the gateway reports it in `GET /api/settings/flags`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LabelsState {
    pub on: bool,
    /// `db` (someone set it) or `default` (never set: off).
    pub source: String,
    pub updated_by: Option<String>,
    pub updated_at: Option<String>,
}

/// Find the kiosk labels row in a `GET /api/settings/flags` answer. `None`
/// when the gateway does not list it — an older stack — which is NOT "off".
pub(crate) fn labels_from_flags(body: &serde_json::Value) -> Option<LabelsState> {
    let row = body["flags"].as_array()?.iter().find(|f| f["key"] == LABELS_SETTING)?;
    Some(LabelsState {
        on: row["value"].as_bool()?,
        source: row["source"].as_str().unwrap_or("unknown").to_string(),
        updated_by: row["updated_by"].as_str().map(str::to_string),
        updated_at: row["updated_at"].as_str().map(str::to_string),
    })
}

/// "ON — set by alice at 2026-10-09T12:00:00Z" / "off (never set; the default)".
pub(crate) fn labels_line(s: &LabelsState) -> String {
    let who = match (&s.updated_by, &s.updated_at) {
        (Some(b), Some(a)) => format!("set by {b} at {a}"),
        (Some(b), None) => format!("set by {b}"),
        (None, Some(a)) => format!("set at {a}"),
        (None, None) if s.source == "default" => "never set; the default".to_string(),
        (None, None) => format!("source: {}", s.source),
    };
    format!("{} ({who})", if s.on { "ON" } else { "off" })
}

/// `noo kiosk labels on|off|status` — the controller's switch for entity
/// names on the kiosk display.
///
/// A `noo_settings` row, written through the same audited route the
/// console's flag toggles use (`POST /api/settings/flags/set`): Operator
/// or Admin only, recorded with who and when, and applied on the display's
/// next graph fetch with no gateway restart. The display's own credential
/// can never reach it. While it is on, the page says `LABELS ON`.
pub fn kiosk_labels(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let want = match args {
        [a] if a == "on" => Some(true),
        [a] if a == "off" => Some(false),
        [a] if a == "status" => None,
        _ => fail(
            g.json,
            ExitCode::Usage,
            "usage",
            "noo kiosk labels takes one of: on, off, status",
            Some("noo kiosk labels status"),
        ),
    };
    if let Some(on) = want {
        crate::http::post_json(
            g,
            "/api/settings/flags/set",
            &json!({ "key": LABELS_SETTING, "value": on }),
            true,
            10,
        );
    }
    let flags = crate::http::get_json(g, "/api/settings/flags", true, 10);
    let Some(state) = labels_from_flags(&flags) else {
        fail(
            g.json,
            ExitCode::RemoteError,
            "unsupported",
            &format!("this gateway does not offer the {LABELS_SETTING} setting — it predates the switch"),
            Some("noo upgrade --stack"),
        )
    };
    if g.json {
        println!("{}", json!({
            "setting": LABELS_SETTING,
            "labels": state.on,
            "source": state.source,
            "updated_by": state.updated_by,
            "updated_at": state.updated_at,
        }));
        return Ok(0);
    }
    match want {
        Some(true) => ui::done("kiosk graph labels ON — the display shows entity names from its next graph fetch (within ~15s)"),
        Some(false) => ui::done("kiosk graph labels off — names leave the display on its next graph fetch (within ~15s)"),
        None => println!("{}", ui::header("kiosk labels", None)),
    }
    println!("{}", ui::kv(&[
        (LABELS_SETTING, if state.on { ui::warn(&labels_line(&state)) } else { labels_line(&state) }),
        ("display", if state.on {
            "entity names and relation types, with LABELS ON in the readout".to_string()
        } else {
            "ids, types and degrees only — no entity names".to_string()
        }),
    ]));
    if state.on {
        ui::guide(&[("noo kiosk labels off", "take entity names off the display")]);
    } else if want.is_none() {
        ui::guide(&[("noo kiosk labels on", "show entity names on the display (audited; LABELS ON is shown)")]);
    }
    Ok(0)
}

/// What the display is being sent right now, asked through its own local
/// proxy — the same path the browser uses, so no credential is read here.
/// `None`: the proxy did not answer, or the gateway predates the switch.
fn labels_via_proxy(port: i64) -> Option<bool> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(8)))
        .build()
        .into();
    let body: serde_json::Value = agent
        .get(&format!("http://127.0.0.1:{port}/api/kiosk/graph"))
        .call()
        .ok()?
        .body_mut()
        .read_json()
        .ok()?;
    seat_labels(&body)
}

/// The `labels` flag of a `/api/kiosk/graph` answer.
pub(crate) fn seat_labels(graph: &serde_json::Value) -> Option<bool> {
    graph.get("labels")?.as_bool()
}

/// The seat's "graph labels" cell.
pub(crate) fn seat_labels_cell(labels: Option<bool>, proxy_listening: bool) -> String {
    match labels {
        Some(true) => ui::warn("ON — entity names are shown on this display (controller: noo kiosk labels off)"),
        Some(false) => "off — no entity names are sent to this display".to_string(),
        None if proxy_listening => ui::muted("unknown (the gateway did not say — an older stack, or the graph did not load)").to_string(),
        None => ui::muted("unknown (the local proxy is not listening)").to_string(),
    }
}

/// `noo kiosk teardown [-y|--yes]` — units and files go; the user and the
/// packages stay (a `userdel` is the operator's, and reversible only by
/// them).
pub fn kiosk_teardown(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    let mut yes = false;
    for a in args {
        match a.as_str() {
            "-y" | "--yes" => yes = true,
            _ => return Err(Unhandled),
        }
    }
    super::confirm_destructive(g, yes, "remove the kiosk seat", "units, launcher and key file (the kiosk user stays)");
    ui::step("stopping units");
    for cmd in [
        "sudo systemctl disable --now kiosk-watchdog.timer",
        "sudo systemctl disable --now kiosk.service",
        "sudo systemctl disable --now kiosk-serve.service",
    ] {
        if let Err(e) = sh(&format!("{cmd} 2>/dev/null")) {
            ui::warned(&e);
        }
    }
    ui::step("removing files");
    let paths = [
        format!("{UNIT_DIR}/kiosk.service"),
        format!("{UNIT_DIR}/kiosk-serve.service"),
        format!("{UNIT_DIR}/kiosk-watchdog.service"),
        format!("{UNIT_DIR}/kiosk-watchdog.timer"),
        format!("{BIN_DIR}/noo-kiosk-launch"),
        format!("{BIN_DIR}/noo-kiosk-cdp"),
        format!("{BIN_DIR}/noo-kiosk-serve"),
        format!("{BIN_DIR}/noo-kiosk-watchdog"),
        ENV_FILE.to_string(),
        LOGIND_CONF.to_string(),
        format!("{STATE_DIR}/token.json"),
        format!("{STATE_DIR}/state.json"),
        // The proxy's reasons moved into state.json, but the LAUNCHER and
        // the watchdog still write this one. Dropping it from the list
        // leaves teardown's own litter behind.
        format!("{STATE_DIR}/last-error"),
        format!("{STATE_DIR}/watchdog.strikes"),
    ];
    if let Err(e) = sh(&format!("sudo rm -f {}", paths.join(" "))) {
        fail(g.json, ExitCode::Generic, "rm", &e, None);
    }

    // Reverse what dedicated mode took away. Removing the logind override
    // above already restores NAutoVTs/ReserveVT to their defaults, but a
    // MASKED getty survives the file being deleted — teardown that leaves
    // it masked hands back a machine with no console login and no override
    // left to explain why.
    if sh_out("systemctl is-enabled getty@.service 2>/dev/null").as_deref() == Some("masked") {
        ui::step("unmasking getty@.service");
        if let Err(e) = sh("sudo systemctl unmask getty@.service") {
            ui::warned(&format!("{e} — run `sudo systemctl unmask getty@.service` by hand or this box has no console login"));
        }
    }
    if sh_out("systemctl is-enabled display-manager.service 2>/dev/null").as_deref() == Some("disabled") {
        ui::step("re-enabling the display manager");
        if let Err(e) = sh("sudo systemctl enable display-manager.service") {
            ui::warned(&format!("{e} — re-enable it by hand if this box should boot to a desktop"));
        }
    }
    let _ = sh("sudo systemctl daemon-reload");
    println!();
    ui::done("kiosk seat removed; the kiosk user and browser profile were left in place");
    println!("{}", ui::note(
        "console logins and the display manager are back as they were; a reboot (or \
         `systemctl restart systemd-logind`) applies the restored VT defaults.",
    ));
    ui::guide(&[
        ("sudo userdel -r kiosk", "removes the user and /var/lib/kiosk, if you are done with the display"),
        ("noo security service-key list", "on the controller: a key marked 'retired scope' is a pre-keyless seat's — revoke it"),
    ]);
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn setup_switches_off_tailscaled_log_upload_through_the_enroll_script() {
        let c = tailscale_logs_off_cmd();
        assert!(c.starts_with("command -v tailscaled"), "a display without tailscale must be a no-op: {c}");
        assert!(c.contains("TS_NO_LOGS_NO_SUPPORT=true") && c.contains("/etc/default/tailscaled"), "{c}");
        assert!(c.contains(crate::vendor::TAILSCALE_UPLOAD_MARKER), "an operator's opt-in must stop the seat re-applying the switch: {c}");
        assert!(c.find("tee -a").unwrap() < c.find("systemctl restart tailscaled").unwrap(), "{c}");
        // And setup actually runs it.
        let body = include_str!("kiosk.rs").split("#[cfg(test)]").next().unwrap();
        assert!(body.contains("sh(&tailscale_logs_off_cmd())"), "kiosk_setup no longer switches the upload off");
        assert!(body.contains("(\"tailscale logs\""), "kiosk status shows no tailscale logs row");
    }

    #[test]
    fn the_display_judges_tailscaled_from_what_it_can_read_unprivileged() {
        let sw = "FLAGS=\"\"\nTS_NO_LOGS_NO_SUPPORT=true\n";
        assert_eq!(tailscale_logs_state(false, false, None, None, None), TsLogs::NotInstalled);
        // Uploading: running, no switch anywhere.
        assert_eq!(tailscale_logs_state(true, false, Some("FLAGS=\"\"\n"), Some("/usr/sbin/tailscaled --state=x"), None), TsLogs::On);
        // The switch on the command line, or in a file the process started after.
        assert_eq!(tailscale_logs_state(true, false, None, Some("tailscaled --no-logs-no-support"), None), TsLogs::Off);
        assert_eq!(tailscale_logs_state(true, false, Some(sw), Some("tailscaled"), Some(true)), TsLogs::Off);
        // A file edited after the process started proves nothing yet.
        assert_eq!(tailscale_logs_state(true, false, Some(sw), Some("tailscaled"), Some(false)), TsLogs::OffAfterRestart);
        // A comment is not the switch.
        assert!(!defaults_have_switch("# TS_NO_LOGS_NO_SUPPORT=true\n"));
        assert_eq!(tailscale_logs_state(true, false, Some("# TS_NO_LOGS_NO_SUPPORT=true\n"), Some("tailscaled"), None), TsLogs::On);
        // The operator's marker turns the FAIL into a visible choice, and only while it uploads.
        assert_eq!(tailscale_logs_state(true, true, None, Some("tailscaled"), None), TsLogs::OperatorChoice);
        assert_eq!(tailscale_logs_state(true, true, Some(sw), Some("tailscaled"), Some(true)), TsLogs::Off);
        assert_eq!(tailscale_logs_state(true, false, None, None, None), TsLogs::NotRunning { configured: false });
    }

    #[test]
    fn the_os_reporters_and_the_process_start_time_are_read_correctly() {
        assert!(os_reporters(false, None, false).is_empty());
        assert_eq!(os_reporters(true, Some("PARTICIPATE=\"yes\"\n"), true), ["motd-news", "popularity-contest", "whoopsie"]);
        assert!(os_reporters(false, Some("PARTICIPATE=\"no\"\n"), false).is_empty());
        // Field 22 counted from the LAST ')' (the comm may hold spaces and parens).
        let stat = "977 (tail (scale) d) S 1 977 977 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 9 0 12345 1 2 3";
        assert_eq!(process_start_unix(stat, 1_000_000, 100), Some(1_000_000 + 123));
        assert_eq!(process_start_unix("garbage", 0, 100), None);
    }

    use super::*;

    /// The proxy asset's own source. `SERVE` is the same bytes the unit
    /// runs, so assertions on it are assertions on the display.
    fn serve_asset() -> &'static str {
        assert!(
            SERVE.contains("noo-kiosk-serve"),
            "SERVE does not look like the proxy — every assertion below would be vacuous"
        );
        SERVE
    }

    /// Pull a python tuple-of-strings literal out of the asset.
    fn py_tuple(src: &str, name: &str) -> Vec<String> {
        let start = src
            .find(&format!("\n{name} = ("))
            .unwrap_or_else(|| panic!("{name} not found in the proxy — this guard is stale"));
        let body = &src[start..];
        let end = body.find(")\n").expect("unterminated tuple");
        body[..end]
            .split('"')
            .filter(|s| s.starts_with('/'))
            .map(str::to_string)
            .collect()
    }

    /// **Two allow-lists that disagree are a tile that cannot load, or a
    /// path the display can reach that the gateway never meant it to.**
    /// The proxy refuses off-list paths locally AND the gateway refuses
    /// them again; that is defence in depth only while the lists match.
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    /// One of the gateway's `&[&str]` allow-lists, by name. Panics rather
    /// than returning empty: a guard that cannot find its subject must
    /// fail, never quietly pass.
    fn gateway_list(name: &str) -> Vec<String> {
        let auth = std::fs::read_to_string(repo_root().join("gateway-rust/src/auth.rs"))
            .expect("gateway auth.rs unreadable");
        let start = auth
            .find(&format!("pub const {name}: &[&str] = &["))
            .unwrap_or_else(|| panic!("{name} not found in auth.rs — this guard is stale"));
        let body = &auth[start..];
        let end = body.find("];").expect("unterminated slice");
        body[..end].split('"').filter(|s| s.starts_with('/')).map(str::to_string).collect()
    }

    /// Every source the kiosk page fetches must be readable with the kiosk
    /// credential.
    ///
    /// The add-ons tile asks for `/health`. That path was in neither the
    /// allow-list nor the gateway's public list, so the proxy refused it,
    /// the source never arrived, and the display reported
    /// `trellion: unknown` — honestly, and for a reason nobody could see
    /// from the screen. The page and the allow-list are written in
    /// different languages, in different directories, and nothing
    /// compared them. This does.
    #[test]
    fn every_source_the_page_fetches_is_allowed() {
        let hook = repo_root().join("ui/apps/web/src/kiosk/useKiosk.ts");
        let Ok(src) = std::fs::read_to_string(&hook) else {
            eprintln!("skipped: {} not in this checkout", hook.display());
            return;
        };
        let mut paths: Vec<String> = src
            .split("client.GET('")
            .skip(1)
            .filter_map(|t| t.split('\'').next())
            .map(str::to_string)
            .collect();
        // The stream is fetched by EventSource, not the typed client.
        if let Some(rest) = src.split("STREAM_PATH = '").nth(1) {
            if let Some(p) = rest.split('\'').next() {
                paths.push(p.to_string());
            }
        }
        assert!(
            paths.len() >= 9,
            "the scrape found {paths:?}; useKiosk.ts must have changed shape"
        );

        let allowed = gateway_list("KIOSK_READ_PATHS");
        let prefixes = gateway_list("KIOSK_READ_PREFIXES");
        for p in &paths {
            assert!(
                allowed.contains(p) || prefixes.iter().any(|pre| p.starts_with(pre)),
                "the kiosk page fetches {p} and the kiosk credential may not read it: \
                 the proxy will 404 it and that tile sits empty forever"
            );
        }
    }

    /// The stream's OTHER contract: the events the gateway sends and the
    /// events the page knows what to do with.
    ///
    /// The allow-list guard covers what the page FETCHES. Nothing covered
    /// what it LISTENS for. An event the gateway emits and the page
    /// ignores is bandwidth to a screen that will not move; an event the
    /// page handles and the gateway never sends is a feature that looks
    /// implemented and is dead — and neither shows up as a failure
    /// anywhere, because both sides are individually correct.
    ///
    /// Dotted names only, on both sides: `hello` is the handshake, not
    /// data, and the page's source keys (`cluster`, `gpus`, …) live in a
    /// different switch entirely.
    #[test]
    fn the_stream_events_both_sides_agree_on() {
        let store = repo_root().join("ui/apps/web/src/kiosk/store.ts");
        let Ok(page_src) = std::fs::read_to_string(&store) else {
            eprintln!("skipped: {} not in this checkout", store.display());
            return;
        };
        // The page: names it switches on.
        let handled: std::collections::BTreeSet<String> = page_src
            .split("case '")
            .skip(1)
            .filter_map(|t| t.split('\'').next())
            .filter(|n| n.matches('.').count() == 1)
            .map(str::to_string)
            .collect();

        // The gateway: names it puts on the wire.
        let gw_src = std::fs::read_to_string(repo_root().join("gateway-rust/src/routes/kiosk.rs"))
            .expect("gateway kiosk.rs unreadable");
        // Two shapes reach the wire: sent directly, or pushed onto the
        // sampler's batch as ("<name>", payload). Both count; scraping only
        // the first found two of six and would have called the other four
        // dead.
        let emitted: std::collections::BTreeSet<String> = gw_src
            .split("sse_event(id(), \"")
            .skip(1)
            .chain(gw_src.split("out.push((\"").skip(1))
            .filter_map(|t| t.split('"').next())
            .filter(|n| n.matches('.').count() == 1)
            .map(str::to_string)
            .collect();

        assert!(handled.len() >= 5, "the page scrape found {handled:?} — store.ts changed shape");
        assert!(emitted.len() >= 5, "the gateway scrape found {emitted:?} — kiosk.rs changed shape");

        let dead: Vec<_> = handled.difference(&emitted).collect();
        assert!(
            dead.is_empty(),
            "the page handles {dead:?} and the gateway never sends it: a feature that looks implemented and is dead"
        );
        let ignored: Vec<_> = emitted.difference(&handled).collect();
        assert!(
            ignored.is_empty(),
            "the gateway sends {ignored:?} and the page ignores it: bandwidth to a screen that will not move"
        );
    }

    #[test]
    fn the_proxy_allowlist_matches_the_gateway() {
        let gw_paths = gateway_list("KIOSK_READ_PATHS");
        let gw_prefixes = gateway_list("KIOSK_READ_PREFIXES");
        assert!(gw_paths.len() >= 8, "read the gateway list wrong: {gw_paths:?}");

        let src = serve_asset();
        assert_eq!(
            py_tuple(src, "READ_PATHS"),
            gw_paths,
            "the proxy's allow-list and auth::KIOSK_READ_PATHS disagree"
        );
        assert_eq!(
            py_tuple(src, "READ_PREFIXES"),
            gw_prefixes,
            "the proxy's prefixes and auth::KIOSK_READ_PREFIXES disagree"
        );
    }

    /// **`noo kiosk status` must not need a password.** It ran as the
    /// operator, could not read the root-owned files, and GUESSED — it
    /// reported `key (pre-keyless — check for a stored key)` on an
    /// install with no key anywhere, which is a security-relevant fact
    /// stated backwards. The published state file is the fix; reading
    /// token.json again "as a fallback" is the regression.
    #[test]
    fn status_reads_no_secret_and_needs_no_privilege() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/kiosk.rs"),
        )
        .expect("own source unreadable");
        let start = src.find("pub fn kiosk_status(").expect("kiosk_status not found — guard is stale");
        let rest = &src[start..];
        // Stop at the NEXT top-level fn. A section banner was not enough:
        // the slice ran on into `kiosk_teardown`, which legitimately
        // deletes token.json, and the guard fired on someone else's line.
        // Reading past your subject is the same class of bug as reading
        // yourself.
        let end = rest[1..]
            .find("\npub fn ")
            .or_else(|| rest[1..].find("\nfn "))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            !body.contains("#[test]"),
            "the guard is reading the test module, so it would pass on its own text"
        );
        assert!(
            !body.contains("fn kiosk_teardown"),
            "the guard is reading past kiosk_status into another function"
        );

        // CODE ONLY. The comments in here explain the rule — "token.json
        // stays 0600 and is NOT read" — and a guard that greps the whole
        // body scores that prose as the violation it forbids. That is the
        // third time a guard in this file has matched its own words.
        let code: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("state.json") && !code.contains("stays 0600"),
            "the comment filter is not working; every assertion below would read prose"
        );
        let body = code.as_str();

        assert!(
            body.contains("state.json"),
            "status does not read the published state file"
        );
        assert!(
            !body.contains("token.json"),
            "status reads token.json — that file is 0600, which is why status asked for sudo, \
             and it holds the token"
        );
        assert!(
            !body.contains("sudo"),
            "status shells out to sudo; a status command that needs a password gets run less often"
        );
        assert!(
            !body.contains("pre-keyless"),
            "the invented mint path is back — absent must read as absent"
        );
    }

    /// The state file is the interface, so its shape is a contract: what
    /// the proxy writes, `status` must be able to read. Exercised by
    /// running the proxy's own publisher as an UNPRIVILEGED process into
    /// a temp dir, then asserting every row status prints is populated —
    /// and that the absent case says so rather than inventing a value.
    /// Source with the test module cut off, so a guard can never match its
    /// own assertions or the prose explaining them — the way two guards in
    /// this file once passed.
    fn own_code(src: &str) -> String {
        let body = src.split("#[cfg(test)]").next().unwrap_or(src);
        body.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `noo kiosk reload` exists as a VERB, not as folklore about a
    /// helper binary. The operator reloaded their display by running
    /// `noo-kiosk-cdp reload` because nothing else was offered, and then
    /// asked — reasonably — why the regular command would not do it.
    #[test]
    fn reloading_the_display_is_a_noo_verb() {
        let own = own_code(include_str!("kiosk.rs"));
        assert!(own.contains("pub fn kiosk_reload"), "this guard is stale: kiosk_reload is gone");
        assert!(
            own.contains("noo-kiosk-cdp reload"),
            "kiosk_reload does not reload anything"
        );
        assert!(
            crate::usage::USAGE.iter().any(|(path, _, _)| *path == ["kiosk", "reload"]),
            "`noo kiosk reload` is not in the help: a verb nobody can discover is not a verb"
        );
    }

    /// The four cases the `console build` cell must tell apart. The third
    /// was reported as the second on a live display: a current console
    /// (stack-v0.2.62, confirmed by curling the served bundle) was called
    /// one from before the stamp existed, because the question never
    /// reached it — the installed helper was too old to have the command.
    #[test]
    fn the_build_cell_blames_the_right_machine() {
        assert_eq!(console_build_row(Some("stack-v0.2.62"), true, false), "stack-v0.2.62");
        assert!(console_build_row(None, false, false).contains("CDP not answering"));

        let stale = console_build_row(None, true, true);
        assert!(stale.contains("noo kiosk setup"), "{stale}");
        assert!(
            !stale.contains("before stack-v0.2.59"),
            "a stale helper is not an old console: {stale}"
        );

        let old_console = console_build_row(None, true, false);
        assert!(old_console.contains("before stack-v0.2.59"), "{old_console}");
    }

    /// Every seat script `setup` installs must be one `status` checks for
    /// staleness. A fifth asset added to setup and forgotten here is a
    /// file that can silently age out on every display in the fleet.
    #[test]
    fn staleness_covers_every_seat_script() {
        let own = own_code(include_str!("kiosk.rs"));
        let installed: std::collections::BTreeSet<&str> = own
            .match_indices("/usr/local/bin/noo-kiosk-")
            .map(|(i, _)| {
                let rest = &own[i..];
                let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || "/-_.".contains(c)));
                &rest[..end.unwrap_or(rest.len())]
            })
            .collect();
        assert!(installed.len() >= 4, "found {installed:?} — this guard is stale");
        for path in installed {
            assert!(
                SEAT_ASSETS.iter().any(|(p, _)| *p == path),
                "{path} is installed on the seat but status never checks whether it is stale"
            );
        }
    }

    /// The console build row: a display that cannot say which build it is
    /// running turns "is my fix live?" into an argument about tag
    /// ancestry between two people who cannot see the machine. Two
    /// sessions spent an evening on exactly that. The page publishes
    /// `window.__nooKioskBuild`; this asserts the path from there to the
    /// operator's terminal exists at every hop, because any one of them
    /// missing leaves the row saying "unknown" forever while looking
    /// implemented.
    #[test]
    fn the_console_build_reaches_the_operator() {
        let cdp = own_code(CDP);
        assert!(
            cdp.contains("__nooKioskBuild"),
            "noo-kiosk-cdp cannot read the build the console publishes"
        );
        assert!(
            cdp.contains(r#"cmd == "build""#),
            "noo-kiosk-cdp has no `build` command for status to call"
        );
        let own = own_code(include_str!("kiosk.rs"));
        assert!(
            own.contains("noo-kiosk-cdp build"),
            "status never asks for the build: the cdp command is dead code"
        );
        assert!(
            own.contains("console build"),
            "status reads the build and does not show it"
        );
    }

    #[test]
    fn published_state_is_world_readable_and_complete() {
        use std::os::unix::fs::PermissionsExt;
        let asset = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/commands/kiosk_assets/noo-kiosk-serve");
        let dir = std::env::temp_dir().join(format!("noo-kiosk-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "g={{'__name__':'x'}}\nexec(open({asset:?}).read(), g)\n\
                 g['publish'](port=8088, minted_at=1789000000, expires_at=1789000900)\n"
            ))
            .env("NOO_KIOSK_STATE", &dir)
            .env("NOO_KIOSK_MODE", "dedicated")
            .env("NOO_KIOSK_VT", "1")
            .env("NOO_KIOSK_VIEW", "health")
            .output()
            .expect("python3 must be present to exercise the state file");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let f = dir.join("state.json");
        let mode = std::fs::metadata(&f).expect("no state.json written").permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "state.json is {mode:o}; an unprivileged status must read it");

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).expect("not JSON");
        for k in ["mode", "vt", "view", "mint", "minted_at", "expires_at", "port", "updated_at"] {
            assert!(!v[k].is_null(), "state.json has no {k}: status would print unknown");
        }
        assert!(
            !v.to_string().contains("eyJ"),
            "a JWT is in the published state — it is world-readable"
        );
        assert!(v["last_error"].is_null(), "a clean publish should carry no error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A proxy that restarts finds a still-valid token.json and reuses it
    /// without minting, so nothing published `expires_at` until the next
    /// renewal — and `status` spent that window claiming the proxy had
    /// "published no state" beside a `state published: 6s ago` row.
    /// Startup must publish what it carried over.
    #[test]
    fn a_restarted_proxy_publishes_the_expiry_it_carried_over() {
        let asset = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/commands/kiosk_assets/noo-kiosk-serve");
        let dir = std::env::temp_dir().join(format!("noo-kiosk-carry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("token.json"),
            r#"{"token":"eyJ.carried.over","expires_at":1789000900}"#,
        )
        .unwrap();

        let out = std::process::Command::new("python3")
            .arg("-c")
            .arg(format!(
                "g={{'__name__':'x'}}\nexec(open({asset:?}).read(), g)\n\
                 g['publish_startup'](g['Credential'](), 8088)\n"
            ))
            .env("NOO_KIOSK_STATE", &dir)
            .env("NOO_KIOSK_MODE", "dedicated")
            .output()
            .expect("python3 must be present");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("state.json")).unwrap()).expect("not JSON");
        assert_eq!(v["expires_at"], 1789000900, "the carried-over expiry was not published");
        assert!(v["minted_at"].is_null(), "startup published a mint it did not perform");
        assert!(!v.to_string().contains("eyJ"), "the carried-over token leaked into the state file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A 0644 file inside a 0700 directory is not readable by anyone.
    ///
    /// This is the half the file mode cannot prove, and it was wrong:
    /// the launcher ran `chmod 0700 "$STATE"` on every boot, so the
    /// published state was sealed behind the directory no matter what
    /// mode it carried. The browser profile is the thing that needs the
    /// closed directory; the state dir is not.
    #[test]
    fn the_state_directory_can_be_traversed_without_privilege() {
        // What setup installs.
        let setup = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/kiosk.rs"),
        )
        .expect("own source unreadable");
        let i = setup
            .find("sudo install -d -m 0755")
            .expect("the state dir is no longer installed world-traversable; status needs sudo again");
        // The profile must NOT have been opened up along with it.
        let after = &setup[i..i + 400];
        assert!(
            after.contains("-m 0700") && after.contains("/profile"),
            "the browser profile lost its closed mode: {after}"
        );

        // What the launcher then does to it every boot, which is what
        // actually decided the answer on the live box.
        assert!(
            !LAUNCH.contains("chmod 0700 \"$STATE\""),
            "the launcher re-locks the state dir at boot, sealing state.json away from status"
        );
        assert!(
            LAUNCH.contains("chmod 0755 \"$STATE\""),
            "the launcher does not open the state dir; a fresh boot would undo setup"
        );
        assert!(
            LAUNCH.contains("chmod 0700 \"$PROFILE\""),
            "the browser profile is no longer locked down"
        );
    }

    /// A wildcard bind would put an AUTHENTICATING proxy on the local
    /// network, where no tailnet ACL applies — and the display would keep
    /// working, so nothing would report it.
    #[test]
    fn the_proxy_binds_loopback_only() {
        let src = serve_asset();
        assert!(src.contains("host=\"127.0.0.1\""), "the proxy does not state its bind address");
        for bad in ["\"0.0.0.0\"", "\"::\"", "host=\"\""] {
            assert!(
                !src.contains(bad),
                "the proxy can bind {bad} — that is an authenticating proxy on the LAN"
            );
        }
    }

    /// The three properties that cannot be read off the source: an
    /// allow-listed path arrives WITH a bearer, an off-list path never
    /// arrives at all, and the stream is relayed in pieces rather than
    /// accumulated. The last one looks fine in review and shows a dead
    /// display. Runs the asset's own `--self-test`, which stands up a stub
    /// upstream and a real proxy on loopback.
    #[test]
    fn the_proxy_really_forwards_refuses_and_streams() {
        let asset = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/commands/kiosk_assets/noo-kiosk-serve");
        let out = std::process::Command::new("python3")
            .arg(&asset)
            .arg("--self-test")
            .output()
            .expect("python3 must be present to exercise the proxy");
        assert!(
            out.status.success(),
            "proxy self-test failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The browser must be pointed at the proxy. Pointed at the gateway it
    /// gets the same bundle with no credential behind it — which is
    /// exactly what shipped, and showed "credential rejected" on a display
    /// while every endpoint answered 200 to anyone who sent a header.
    #[test]
    fn the_launcher_points_at_the_proxy_and_injects_nothing() {
        assert!(
            LAUNCH.contains("PAGE=\"http://127.0.0.1:${SERVE_PORT}/kiosk.html"),
            "the launcher does not point the browser at the local proxy"
        );
        assert!(
            !LAUNCH.contains("noo-kiosk-cdp inject"),
            "the launcher still injects a token the page does not read"
        );
        assert!(
            !LAUNCH.contains("${NOO_KIOSK_URL%/}/kiosk.html"),
            "the launcher still builds the page URL from the controller"
        );
    }

    /// `Requires=`, not `Wants=`: a browser whose proxy is down renders a
    /// connection error, where the page's own band would have said what
    /// was wrong.
    #[test]
    fn the_seat_requires_the_proxy() {
        let u = render_kiosk_service("kiosk", Mode::Dedicated, 1);
        assert!(u.contains("Requires=kiosk-serve.service"), "{u}");
        assert!(u.contains("After=") && u.contains("kiosk-serve.service"), "{u}");
        let s = render_serve_service("kiosk");
        assert!(s.contains("ExecStart=/usr/local/bin/noo-kiosk-serve"), "{s}");
        assert!(s.contains("User=kiosk"), "{s}");
    }

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    // ── the three bugs the first live bring-up found ──────────────────

    /// Bug 1, as it ended up. The original fault was injecting a token
    /// before the page had committed to the controller's origin, so it
    /// landed on about:blank and every call 401'd while the dashboard
    /// rendered. `noo kiosk serve` removed the premise: the page holds no
    /// credential, so there is nothing to inject and no origin to race.
    ///
    /// What must stay true is the shape that replaced it — the browser is
    /// pointed at the LOCAL PROXY and the launcher never touches a token.
    #[test]
    fn the_launcher_hands_the_browser_to_the_local_proxy() {
        assert!(
            LAUNCH.contains("127.0.0.1"),
            "the launcher does not point the browser at the local proxy — if it opens the \
             controller directly the page sends no credential and nothing loads"
        );
        for gone in ["noo-kiosk-cdp inject", "noo-kiosk-cdp start ", "noo-kiosk-cdp mint"] {
            assert!(
                !LAUNCH.contains(gone),
                "launcher runs `{gone}` again — the proxy owns the credential, and a second \
                 place minting or injecting is how expiry gets tracked twice and neither wins"
            );
        }
    }

    /// Bug 2. A failure has to be readable somewhere we control. The
    /// journal carried none of the launcher's output on the live box.
    #[test]
    fn every_launcher_failure_records_a_reason() {
        assert!(LAUNCH.contains("last-error"), "launcher records no durable reason");
        assert!(WATCHDOG.contains("last-error"), "watchdog records no durable reason");
        // The old text claimed a retry that never happened.
        assert!(
            !LAUNCH.contains("retrying in 30s"),
            "launcher still claims it retries after 30s; it exits and systemd restarts it"
        );
        // Each failure path goes through fail(), not a bare echo.
        assert!(LAUNCH.contains("fail \""), "launcher has a failure path that does not call fail()");
    }

    /// Bug 3a. `is-enabled` prints `masked` and exits 1, so reading it
    /// through a helper that discards non-zero exits reported the
    /// display's console logins as NOT masked while they were masked.
    /// Three answers, and "unknown" must never render as "off".
    #[test]
    fn masked_is_three_answers_not_two() {
        assert_eq!(masked_from_is_enabled(Some("masked")), Some(true));
        assert_eq!(masked_from_is_enabled(Some("masked-runtime")), Some(true));
        assert_eq!(masked_from_is_enabled(Some("enabled")), Some(false));
        assert_eq!(masked_from_is_enabled(Some("disabled")), Some(false));
        // Could not tell — NOT "not masked".
        assert_eq!(masked_from_is_enabled(None), None);
        assert_eq!(masked_from_is_enabled(Some("")), None);
    }

    /// Bug 3b. The mint lane is a fact only the proxy holds. When it has
    /// not published one, that absence must not be reported as the
    /// retired key lane — it once was, on a box with no key anywhere.
    ///
    /// Asserted on the DECISION, not on the source. The first version of
    /// this guard grepped for one spelling of the old fallback and passed
    /// happily when the same bug was reintroduced a different way.
    #[test]
    fn an_unknown_mint_lane_is_not_evidence_of_the_key_lane() {
        let unknown = mint_path_row(None);
        assert!(
            !unknown.contains("pre-keyless") && !unknown.contains("stored key"),
            "an unpublished mint lane is reported as the key lane: {unknown}"
        );
        assert!(unknown.contains("unknown"), "no distinct 'we cannot tell' answer: {unknown}");

        // The two answers we CAN make must still be made.
        assert!(mint_path_row(Some("tailnet")).contains("no stored secret"));
        let keyed = mint_path_row(Some("key"));
        assert!(keyed.contains("revoke"), "a real key-lane token must still say so: {keyed}");
    }

    /// Read the declared policy, refusing to return something that is not
    /// recognisably it — otherwise every assertion built on it passes
    /// vacuously the day the file moves or is emptied.
    fn declared_acl() -> (std::path::PathBuf, String) {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = repo.join("config/tailscale-acl.hujson");
        let acl = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("declared tailnet policy unreadable at {}: {e}", path.display()));
        assert!(
            acl.contains("\"tagOwners\"") && acl.contains("\"acls\""),
            "{} does not look like the tailnet policy — assertions on it would be vacuous",
            path.display()
        );
        (path, acl)
    }

    /// The class, not the instance: `tag:kiosk` was the first tag this CLI
    /// wrote over the API without declaring, and the next one added would
    /// repeat it. `ensure_tag_owner` refuses anything off this list, so the
    /// list plus this test is what makes the two edits inseparable.
    #[test]
    fn the_declared_acl_carries_every_api_tag() {
        let (path, acl) = declared_acl();
        for tag in crate::commands::cluster_provision::API_DECLARED_TAGS {
            assert!(
                acl.contains(&format!("\"{tag}\"")),
                "{tag} can be written to the live tailnet policy by this CLI but is not in {} — \
                 the next `noo security tailnet policy --push` pushes that file wholesale and would delete it",
                path.display()
            );
        }
    }

    /// The refusal that makes the list load-bearing rather than advisory.
    /// Runs offline: the check precedes the API-key lookup on purpose.
    #[test]
    fn an_undeclared_tag_is_refused_before_the_network() {
        // `match` rather than `expect_err`: the Ok variant carries no Debug,
        // and giving it one just to phrase a test is the tail wagging the dog.
        match crate::commands::cluster_provision::ensure_tag_owner("tag:invented") {
            Ok(_) => panic!("an undeclared tag must be refused, not written"),
            Err(e) => assert!(
                e.contains("tailscale-acl.hujson"),
                "the refusal must name the declared file so the reader knows where to add it: {e}"
            ),
        }
    }

    /// The API edit in `kiosk_invite` and the declared policy must agree, or
    /// a controller bootstrap deletes the display's only grant. Reads the
    /// real file rather than a fixture, because a fixture would agree with
    /// itself forever while the shipped policy drifted.
    #[test]
    fn the_declared_acl_carries_the_kiosk_grant() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = repo.join("config/tailscale-acl.hujson");
        let acl = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("declared tailnet policy unreadable at {}: {e}", path.display()));

        // Guard the guard: if the file is ever emptied or moved, the checks
        // below would pass on a stub. Anchor on something unrelated to the
        // kiosk that the policy has always had.
        assert!(
            acl.contains("\"tag:controller\"") && acl.contains("\"acls\""),
            "{} does not look like the tailnet policy — the assertions below would be vacuous",
            path.display()
        );

        assert!(
            acl.contains("\"tag:kiosk\""),
            "tag:kiosk is missing from the DECLARED policy ({}). `noo kiosk invite` adds it \
             over the API, but `noo security tailnet policy --push` pushes this file wholesale and would \
             delete it — every tagged display loses :443, quietly.",
            path.display()
        );
        assert!(
            acl.contains("tag:controller:443"),
            "the declared policy grants no :443 — a display reaches the gateway only through \
             Tailscale Serve"
        );
        // The display must not be handed :8080: Chromium will not trust the
        // cluster CA from the OS store, and `kiosk setup` refuses that URL.
        let kiosk_rule = acl
            .split("\"tag:kiosk\"")
            .nth(2)
            .and_then(|s| s.split('}').next())
            .unwrap_or("");
        assert!(
            !kiosk_rule.contains("8080"),
            "the kiosk grant lists :8080; that port serves the cluster-CA cert, which is a \
             certificate wall on a screen with no keyboard"
        );
    }

    /// One of the files `install_text` writes is the display's durable
    /// service key, so it must never exist anywhere but its destination.
    /// Asserted against the source, because the property is "no
    /// intermediate file" and the absence of a file is not observable
    /// from a passing call — the old code worked fine and was still
    /// wrong.
    #[test]
    fn the_key_is_piped_and_never_staged_in_tmp() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/kiosk.rs"),
        )
        .expect("own source unreadable");
        let start = src.find("fn install_text(").expect("install_text not found — this guard is stale");
        // End at the next top-level fn so the assertions cover this body only.
        let body = &src[start..];
        let end = body[1..].find("\nfn ").map(|i| i + 1).unwrap_or(body.len());
        let body = &body[..end];

        assert!(
            body.contains("/dev/stdin"),
            "install_text must feed content over a pipe, not stage a file"
        );
        assert!(
            !body.contains("temp_dir"),
            "install_text stages through a temp file again: the service key would sit in /tmp \
             at a pid-derived path, created under the umask and chmod'd only afterwards"
        );
        assert!(
            !body.contains("fs::write"),
            "install_text writes a file itself again — `install -m` must create the only copy"
        );
    }

    #[test]
    fn invite_parses_and_validates_the_name() {
        let a = parse_invite(&argv(&["host5", "--expiry-minutes", "30", "--url", "https://c.tail.ts.net/"])).unwrap();
        assert_eq!(a, InviteArgs { name: "host5".into(), expiry_minutes: 30, url: Some("https://c.tail.ts.net".into()) });
        let d = parse_invite(&argv(&["hallway-1"])).unwrap();
        assert_eq!((d.expiry_minutes, d.url), (60, None));
        assert!(parse_invite(&argv(&[])).unwrap_err().contains("usage"));
        assert!(parse_invite(&argv(&["bad name"])).unwrap_err().contains("[A-Za-z0-9_-]"));
        // --rpm refuses rather than silently doing nothing.
        assert!(parse_invite(&argv(&["x", "--rpm", "60"])).unwrap_err().contains("retired"));
    }

    #[test]
    fn the_unit_takes_tty1_from_the_greeter() {
        // Dedicated only — taking tty1 from the greeter is what that mode
        // is. Shared mode's opposite property is asserted separately.
        let u = render_kiosk_service("kiosk", Mode::Dedicated, DEDICATED_VT);
        assert!(u.contains("Conflicts=getty@tty1.service display-manager.service"));
        assert!(u.contains("TTYPath=/dev/tty1"));
    }

    /// The page reads its settings from the query string; the SEAT is the
    /// only thing that ever builds that query string on a real display.
    /// So every parameter the page understands needs a way to be set
    /// from `noo kiosk setup` — or it is a feature that exists and
    /// cannot be reached.
    ///
    /// `?poll=` was exactly that. The page had supported it since the
    /// graph view shipped, the seat had no flag for it, and the only way
    /// to switch it on was to drive the browser by hand with
    /// `noo-kiosk-cdp navigate` — which does not survive a restart.
    ///
    /// `labels` is not a page parameter at all any more, and that is
    /// asserted too: names on a hallway display are the CONTROLLER's
    /// decision (`kiosk.graph_labels`, `noo kiosk labels on|off`), audited
    /// and visible as LABELS ON — never something a seat is configured
    /// into once and left in, and never something the kiosk credential
    /// can ask for.
    #[test]
    fn every_page_parameter_can_be_set_from_the_seat() {
        let main_tsx = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("ui/apps/web/src/kiosk/main.tsx");
        let Ok(src) = std::fs::read_to_string(&main_tsx) else {
            // The bundle is a subtree; in a checkout without it there is
            // nothing to compare against. Skipping silently is how a
            // guard stops guarding, so say so.
            eprintln!("skipped: {} not in this checkout", main_tsx.display());
            return;
        };
        let params: Vec<String> = src
            .split("params.get('")
            .skip(1)
            .filter_map(|t| t.split('\'').next())
            .map(str::to_string)
            .collect();
        assert!(
            params.contains(&"poll".to_string()) && params.contains(&"view".to_string()),
            "the parameter scrape found {params:?}; main.tsx must have changed shape"
        );
        assert!(
            !params.contains(&"labels".to_string()),
            "the page reads ?labels= again — names are the controller's switch \
             (kiosk.graph_labels), not a URL a seat or a lifted token can set"
        );
        assert!(
            !LAUNCH.contains("labels="),
            "the seat sets ?labels= — entity names would be on a hallway screen by \
             configuration rather than by the operator's audited switch"
        );
        for p in &params {
            assert!(
                LAUNCH.contains(&format!("{p}=$")) || LAUNCH.contains(&format!("{p}=${{")),
                "the page reads ?{p}= and the launcher never sets it: an operator can only \
                 reach it by driving the browser by hand, which no restart survives"
            );
        }
    }

    #[test]
    fn setup_parses_the_full_shape() {
        let a = parse_setup(&argv(&["--mode", "dedicated", "--url", "https://c.tail.ts.net/", "--view", "graph", "--rotate", "30", "--poll", "10", "--dry-run"])).unwrap();
        assert_eq!(a, SetupArgs { url: "https://c.tail.ts.net".into(), user: "kiosk".into(), view: "graph".into(), rotate: Some(30), poll: Some(10), quality: None, dry_run: true, yes: false, browser: None, mode: Mode::Dedicated, vt: DEDICATED_VT });
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--poll", "soon"])).unwrap_err().contains("--poll"));
        let q = parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--quality", "lean"])).unwrap();
        assert_eq!(q.quality.as_deref(), Some("lean"));
        assert!(render_env(&q).contains("NOO_KIOSK_QUALITY=lean\n"), "the seat did not keep the quality it was given");
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--quality", "medium"])).unwrap_err().contains("--quality"));
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--quality"])).unwrap_err().contains("--quality"));
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--poll"])).unwrap_err().contains("--poll"));
    }

    #[test]
    fn setup_requires_a_url_and_a_known_view() {
        assert!(parse_setup(&argv(&[])).unwrap_err().contains("--url"));
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--view", "clock"])).unwrap_err().contains("--view"));
        let b = parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--browser", "google-chrome-stable"])).unwrap();
        assert_eq!(b.browser.as_deref(), Some("google-chrome-stable"));
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--browser"])).unwrap_err().contains("--browser"));
        assert!(parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--bogus"])).unwrap_err().contains("--bogus"));
    }

    /// The retired flags must REFUSE, not be silently ignored. An
    /// operator pasting last week's command would otherwise believe a key
    /// was stored while the display quietly minted by tailnet proof —
    /// leaving them with a wrong model of what the box holds and an
    /// un-revoked service key they think is load-bearing.
    #[test]
    fn the_retired_key_flags_refuse_loudly() {
        for flag in ["--key", "--key-stdin"] {
            let e = parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", flag, "sk-old"])).unwrap_err();
            assert!(e.contains("retired"), "{flag}: {e}");
            assert!(e.contains("service-key revoke"), "{flag} must say how to revoke the old key: {e}");
        }
    }

    #[test]
    fn the_gateway_listener_is_refused_with_the_reason() {
        let e = validate_url("https://noo-controller.tail.ts.net:8080").unwrap_err();
        assert!(e.contains("certificate wall"), "{e}");
        assert!(e.contains("tailscale serve"), "{e}");
        assert!(validate_url("http://noo-controller.tail.ts.net").unwrap_err().contains("https"));
        assert!(validate_url("https://noo-controller.tail.ts.net").is_ok());
        assert!(validate_url("https://noo-controller.tail.ts.net/").is_ok());
    }

    fn sample() -> SetupArgs {
        SetupArgs { url: "https://c.tail.ts.net".into(), user: "kiosk".into(), view: "health".into(), rotate: None, poll: None, quality: None, dry_run: false, yes: false, browser: None, mode: Mode::Dedicated, vt: DEDICATED_VT }
    }

    #[test]
    fn env_file_carries_every_variable_the_scripts_read() {
        let env = render_env(&sample());
        for k in ["NOO_KIOSK_URL=https://c.tail.ts.net", "NOO_KIOSK_VIEW=health", "NOO_KIOSK_ROTATE=\n", "NOO_KIOSK_POLL=\n", "NOO_KIOSK_QUALITY=\n", "NOO_KIOSK_STATE=/var/lib/kiosk", "NOO_KIOSK_USER=kiosk", "NOO_KIOSK_DIALBACK_PORT=8099", "NOO_KIOSK_MODE=dedicated", "NOO_KIOSK_VT=1"] {
            assert!(env.contains(k), "missing {k}");
        }
        // The whole point of the keyless mint: nothing durable is written.
        assert!(!env.contains("NOO_KIOSK_KEY"), "the env file must carry no key");
        // Every variable the scripts read is one the env file writes.
        for script in [LAUNCH, WATCHDOG, CDP] {
            for var in ["NOO_KIOSK_URL", "NOO_KIOSK_VIEW", "NOO_KIOSK_ROTATE", "NOO_KIOSK_POLL", "NOO_KIOSK_STATE", "NOO_KIOSK_USER", "NOO_KIOSK_DIALBACK_PORT", "NOO_KIOSK_MODE", "NOO_KIOSK_VT"] {
                if script.contains(var) {
                    assert!(env.contains(&format!("{var}=")), "{var} read but not written");
                }
            }
        }
    }

    #[test]
    fn kiosk_unit_is_a_seat_on_tty1_for_the_kiosk_user() {
        let u = render_kiosk_service("kiosk", Mode::Dedicated, DEDICATED_VT);
        for line in ["User=kiosk", "PAMName=login", "TTYPath=/dev/tty1", "StandardInput=tty", "Conflicts=getty@tty1.service",
                     "EnvironmentFile=/etc/default/kiosk", "ExecStart=/usr/local/bin/noo-kiosk-launch", "Restart=always", "WantedBy=graphical.target"] {
            assert!(u.contains(line), "missing {line}");
        }
    }

    /// `--mode` has no default ON PURPOSE. A default here is how someone
    /// asking for a dashboard loses their desktop, so the absence must be
    /// a refusal rather than a guess.
    #[test]
    fn setup_refuses_to_choose_the_mode_for_you() {
        let e = parse_setup(&argv(&["--url", "https://c.tail.ts.net"])).unwrap_err();
        assert!(e.contains("--mode is required"), "{e}");
        // The refusal has to say what the two DO, not just name them — the
        // operator is choosing whether this machine stays usable.
        assert!(e.contains("dedicated") && e.contains("shared"), "{e}");
        assert!(
            parse_setup(&argv(&["--mode", "kiosk", "--url", "https://x"])).unwrap_err().contains("--mode must be"),
        );
    }

    /// The safety property of shared mode, asserted rather than intended:
    /// its unit must not claim tty1 and must not name the display manager.
    /// Either would take the laptop's desktop away on the next boot, which
    /// is exactly what shared mode exists to avoid.
    #[test]
    fn shared_mode_never_touches_the_desktops_terminal_or_its_greeter() {
        let u = render_kiosk_service("kiosk", Mode::Shared, SHARED_DEFAULT_VT);
        // Assert the DIRECTIVES, not the prose: the comment block
        // legitimately mentions tty1 while explaining that the desktop
        // keeps it, and a substring check on the whole file fails on its
        // own explanation.
        let directives: String = u
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!directives.contains("display-manager"), "shared mode conflicts with the desktop's greeter:\n{directives}");
        assert!(!directives.contains("tty1"), "shared mode claims tty1, which the desktop is using:\n{directives}");
        assert!(!directives.contains("Conflicts="), "shared mode conflicts with something:\n{directives}");
        assert!(directives.contains("TTYPath=/dev/tty8") && directives.contains("UtmpIdentifier=tty8"), "{directives}");

        // …and dedicated mode must still do all three, or it is not taking
        // the seat it claims to.
        let d = render_kiosk_service("kiosk", Mode::Dedicated, DEDICATED_VT);
        assert!(d.contains("Conflicts=getty@tty1.service display-manager.service"), "{d}");
    }

    /// The VT hardening is dedicated-only. On a shared box these lines
    /// would remove the console logins its owner uses to get in.
    #[test]
    fn only_dedicated_mode_shuts_off_the_login_terminals() {
        let d = render_logind_conf(Mode::Dedicated);
        assert!(d.contains("NAutoVTs=0"), "dedicated mode leaves VTs autospawning:\n{d}");
        assert!(d.contains("ReserveVT=0"), "dedicated mode leaves a reserved VT:\n{d}");

        let s = render_logind_conf(Mode::Shared);
        assert!(!s.contains("NAutoVTs"), "shared mode disables the laptop's console logins:\n{s}");
        assert!(!s.contains("ReserveVT"), "shared mode disables the laptop's reserved VT:\n{s}");
    }

    /// A shared display on a VT the desktop owns is a shared display that
    /// fights the desktop for the screen.
    #[test]
    fn shared_mode_will_not_take_the_desktops_vt() {
        let e = parse_setup(&argv(&["--mode", "shared", "--url", "https://x", "--vt", "1"])).unwrap_err();
        assert!(e.contains("pick 2"), "{e}");
        let a = parse_setup(&argv(&["--mode", "shared", "--url", "https://x"])).unwrap();
        assert_eq!(a.vt, SHARED_DEFAULT_VT, "shared mode must default off tty1");
        let v = parse_setup(&argv(&["--mode", "shared", "--url", "https://x", "--vt", "9"])).unwrap();
        assert_eq!(v.vt, 9);
        // --vt on a dedicated seat is a misunderstanding worth refusing:
        // taking tty1 is the entire point of that mode.
        assert!(
            parse_setup(&argv(&["--mode", "dedicated", "--url", "https://x", "--vt", "8"]))
                .unwrap_err().contains("--vt is for --mode shared"),
        );
    }

    /// Teardown must UNMASK. Removing the logind override restores the VT
    /// defaults, but a masked getty survives the file being deleted — a
    /// teardown that skips this hands back a box with no console login and
    /// nothing left on disk to explain why.
    #[test]
    fn teardown_reverses_the_getty_mask() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/kiosk.rs"),
        ).expect("own source unreadable");
        let start = src.find("pub fn kiosk_teardown(").expect("kiosk_teardown not found — this guard is stale");
        let body = &src[start..];
        // Stop at the test module. `kiosk_teardown` is the LAST `pub fn` in
        // this file, so slicing to the next one ran to end-of-file and swept
        // in this very test — whose assertions spell out the exact calls
        // being searched for. The guard found itself and passed with the
        // real calls gutted. Planting that is how it was caught.
        let end = body
            .find("\n#[cfg(test)]")
            .expect("the test module moved — this guard would read itself and always pass");
        let body = &body[..end];
        assert!(
            !body.contains("fn teardown_reverses_the_getty_mask"),
            "the guard is reading its own assertions; it would pass whatever teardown does"
        );
        // Assert the CALL, not a mention. The first version of this guard
        // looked for the bare string and passed happily when the `sh()`
        // beside it was gutted, because the failure message still spelled
        // the command out — a guard reading the prose that explains the
        // thing rather than the thing. Caught by planting exactly that.
        assert!(
            body.contains(r#"sh("sudo systemctl unmask getty@.service")"#),
            "teardown does not RUN the unmask (a message mentioning it is not the same thing): \
             the box would keep no console login"
        );
        assert!(
            body.contains(r#"sh("sudo systemctl enable display-manager.service")"#),
            "teardown does not RUN the display-manager re-enable: the box would not boot to a \
             desktop again"
        );
    }

    #[test]
    fn watchdog_ticks_every_minute_as_a_oneshot() {
        assert!(render_watchdog_timer().contains("OnUnitActiveSec=60s"));
        let s = render_watchdog_service();
        assert!(s.contains("Type=oneshot"));
        assert!(s.contains("ExecStart=/usr/local/bin/noo-kiosk-watchdog"));
        assert!(!s.contains("User="), "the watchdog must be root: it restarts kiosk.service");
    }

    #[test]
    fn logind_overrides_keep_the_lid_and_idle_from_sleeping_the_display() {
        for m in [Mode::Dedicated, Mode::Shared] {
            let c = render_logind_conf(m);
            assert!(c.contains("HandleLidSwitch=ignore"), "{}", m.as_str());
            assert!(c.contains("IdleAction=ignore"), "{}", m.as_str());
        }
    }

    /// The launcher handles no credential at all now — the proxy does. It
    /// used to mint and inject, and the injection half never worked: the
    /// page stopped reading localStorage on 2026-09-06, so a token was
    /// being written where nothing read it while the display showed
    /// "credential rejected".
    #[test]
    fn the_launcher_handles_no_credential_at_all() {
        assert!(!LAUNCH.contains("token="), "launcher puts a token in a URL");
        assert!(
            !LAUNCH.contains("noo-kiosk-cdp mint"),
            "the launcher mints; the proxy that USES the token should, or expiry is tracked twice"
        );
        assert!(LAUNCH.contains("--remote-debugging-port=\"$CDP_PORT\""));
        assert!(LAUNCH.contains("kiosk.html?view="));
        // The mint itself is unchanged and still keyless — it just moved.
        assert!(CDP.contains("__nooKioskHeartbeat"));
        assert!(CDP.contains("/api/kiosk/token/tailnet"), "the mint must use the keyless route");
        assert!(
            SERVE.contains("\"mint\""),
            "the proxy does not mint — nothing would hold a credential"
        );
    }

    /// The debugging port is a full control surface — it reads the token
    /// out of localStorage and drives the browser. Loopback is the ONLY
    /// thing bounding it (TCP has no file permissions, so any local user
    /// qualifies), which makes widening it a silent catastrophe rather
    /// than a visible one: everything keeps working.
    ///
    /// Asserted on the flags rather than on behaviour because this cannot
    /// be exercised without a browser, and a test that quietly skips is
    /// worse than one that reads the launcher.
    #[test]
    fn the_debugging_port_never_leaves_loopback() {
        // Stated, not defaulted: Chrome's default is loopback today, and a
        // default is not a guarantee.
        assert!(
            LAUNCH.contains("--remote-debugging-address=127.0.0.1"),
            "the launcher relies on Chrome's default bind address instead of stating it"
        );
        for bad in ["--remote-debugging-address=0.0.0.0", "--remote-debugging-address=::", "--remote-allow-origins=*"] {
            assert!(
                !LAUNCH.contains(bad),
                "{bad} in the launcher: the debugging port would be reachable off this machine, \
                 and whoever reaches it reads the display's token"
            );
        }
        // The profile holds the token at rest (localStorage lives in the
        // user-data-dir), so it must not be world-readable.
        assert!(LAUNCH.contains("chmod 0700 \"$PROFILE\""), "the profile holding the token is not 0700");
    }

    /// No script may read a stored key any more. If one did, `setup` no
    /// longer writes it, so the failure would be a display that mints
    /// fine today and dies the day someone "fixes" the env file — and
    /// since 2026-09-30 the controller has no key lane to mint from at all.
    ///
    /// The proxy is the one script allowed to NAME the variable, and only
    /// to log that a leftover value is ignored (`warn_retired_key`): the
    /// name appears exactly once, in `RETIRED_KEY_VARS`, and nothing reads
    /// it into a header.
    #[test]
    fn nothing_reads_a_stored_key() {
        for (name, script) in [("launch", LAUNCH), ("watchdog", WATCHDOG), ("cdp", CDP)] {
            assert!(!script.contains("NOO_KIOSK_KEY"), "{name} still reads NOO_KIOSK_KEY");
        }
        let serve = include_str!("kiosk_assets/noo-kiosk-serve");
        let hits: Vec<&str> = serve.lines().filter(|l| l.contains("NOO_KIOSK_KEY")).collect();
        let code_hits: Vec<&&str> = hits
            .iter()
            .filter(|l| !l.trim_start().starts_with('#') && !l.contains("check("))
            .collect();
        assert_eq!(
            code_hits.len(),
            1,
            "serve names NOO_KIOSK_KEY outside its one retired-name declaration: {code_hits:?}"
        );
        assert!(code_hits[0].contains("RETIRED_KEY_VARS = "), "{:?}", code_hits[0]);
        assert!(serve.contains("is set but IGNORED"), "the ignore line is gone");
        // The only mint is the tailnet one.
        // (Spelled in two parts: tests/test_cli_routes_exist.py reads every
        // path literal in the CLI as a route the CLI calls.)
        let any_mint = ["api/kiosk/", "token"].concat();
        let cdp_mints: Vec<&str> = CDP.lines().filter(|l| l.contains(&any_mint)).collect();
        assert!(!cdp_mints.is_empty() && cdp_mints.iter().all(|l| l.contains("/api/kiosk/token/tailnet")), "{cdp_mints:?}");
    }

    /// **The guard that matters most in this change.**
    ///
    /// The dialback listener must bind the display's own tailnet address,
    /// never a wildcard. A wildcard bind also answers on the LOCAL
    /// NETWORK, where no tailnet ACL applies — the
    /// `tag:controller -> tag:kiosk:8099` grant would then bound nothing,
    /// while every functional test still passed, because the mint
    /// succeeds either way. Nothing would ever report the difference.
    ///
    /// Asserted against the source because the property is about what the
    /// bind address IS NOT, which a successful mint cannot demonstrate.
    #[test]
    fn the_dialback_listener_never_binds_a_wildcard() {
        assert!(
            CDP.contains("def bind_proof(ip, port, nonce)") && CDP.contains("HTTPServer((ip, port)"),
            "the mint must bind the RESOLVED tailnet address explicitly"
        );
        for wildcard in ["0.0.0.0", "HTTPServer((\"\"", "bind((\"\"", "HTTPServer((''"] {
            assert!(
                !CDP.contains(wildcard),
                "the dialback listener binds a wildcard ({wildcard}) — it would be reachable from \
                 the local network, where the tailnet ACL does not apply, and the mint would still \
                 succeed so nothing would report it"
            );
        }
        // And it must REFUSE when the address cannot be resolved. A
        // fallback here is the bug, not the safety net.
        assert!(
            CDP.contains("refusing to mint"),
            "the mint must refuse when the tailnet address is unresolvable, never fall back"
        );
        // The listener is released on every exit path, failures included.
        assert!(CDP.contains("finally:") && CDP.contains("srv.server_close()"),
            "the listener must close on every exit path, including the failures");
    }

    /// The port the display serves its nonce on and the port the declared
    /// policy grants must be the same number. They are written in two
    /// files that no compiler relates.
    #[test]
    fn the_dialback_port_matches_the_declared_grant() {
        let (path, acl) = declared_acl();
        assert!(
            acl.contains(&format!("tag:kiosk:{DIALBACK_PORT}")),
            "the declared policy grants no tag:controller -> tag:kiosk:{DIALBACK_PORT} in {} — \
             the dialback would be dropped and every mint would hang",
            path.display()
        );
        assert!(render_env(&sample()).contains(&format!("NOO_KIOSK_DIALBACK_PORT={DIALBACK_PORT}")));
    }

    /// There is no longer anything for a dry run to mask, which is the
    /// point. Asserted on the VARIABLES rather than the prose — the file's
    /// comment says "THERE IS NO KEY HERE", and a naive substring check on
    /// "key" fails on the very sentence that documents the property.
    #[test]
    fn a_dry_run_has_no_secret_left_to_mask() {
        let env = render_env(&sample());
        for line in env.lines().filter(|l| !l.trim_start().starts_with('#')) {
            let name = line.split('=').next().unwrap_or("");
            assert!(
                !name.to_lowercase().contains("key") && !name.to_lowercase().contains("secret"),
                "the env file assigns something secret-shaped: {line}"
            );
        }
    }

    #[test]
    fn the_labels_switch_is_read_from_the_flags_list() {
        let body = json!({"flags": [
            {"key": "CLOUD_PROVIDERS_ENABLED", "value": true, "source": "env"},
            {"key": "kiosk.graph_labels", "value": true, "source": "db",
             "updated_by": "alice", "updated_at": "2026-10-09T12:00:00Z"},
        ]});
        let s = labels_from_flags(&body).expect("the row was not found");
        assert!(s.on);
        assert_eq!(labels_line(&s), "ON (set by alice at 2026-10-09T12:00:00Z)");

        let off = labels_from_flags(&json!({"flags": [
            {"key": "kiosk.graph_labels", "value": false, "source": "default", "updated_by": null, "updated_at": null},
        ]})).unwrap();
        assert!(!off.on);
        assert_eq!(labels_line(&off), "off (never set; the default)");

        // An older gateway lists no such row: that is "unknown", never "off".
        assert_eq!(labels_from_flags(&json!({"flags": [{"key": "CLOUD_PROVIDERS_ENABLED", "value": false}]})), None);
        assert_eq!(labels_from_flags(&json!({})), None);
    }

    #[test]
    fn the_seat_reads_labels_from_the_graph_answer_and_never_guesses() {
        assert_eq!(seat_labels(&json!({"labels": true, "nodes": []})), Some(true));
        assert_eq!(seat_labels(&json!({"labels": false})), Some(false));
        assert_eq!(seat_labels(&json!({"nodes": []})), None, "an older gateway is unknown, not off");
        assert!(seat_labels_cell(Some(true), true).contains("ON"));
        assert!(seat_labels_cell(None, true).contains("unknown"));
        assert!(seat_labels_cell(None, false).contains("unknown"));
    }

    #[test]
    fn labels_takes_exactly_on_off_or_status_and_writes_the_registered_key() {
        assert_eq!(LABELS_SETTING, "kiosk.graph_labels");
        let gw = std::fs::read_to_string(repo_root().join("gateway-rust/src/routes/settings.rs"))
            .expect("gateway settings.rs unreadable");
        assert!(
            gw.contains(&format!("KIOSK_GRAPH_LABELS: &str = \"{LABELS_SETTING}\"")),
            "the CLI writes {LABELS_SETTING} and the gateway registry does not register it"
        );
    }

    #[test]
    fn display_manager_is_disabled_only_by_dedicated_mode_when_enabled() {
        assert!(display_manager_will_be_disabled(Mode::Dedicated, Some("enabled")));
        assert!(!display_manager_will_be_disabled(Mode::Dedicated, Some("disabled")));
        assert!(!display_manager_will_be_disabled(Mode::Dedicated, None));
        assert!(!display_manager_will_be_disabled(Mode::Shared, Some("enabled")));
    }

    #[test]
    fn setup_confirms_before_it_disables_the_display_manager() {
        let src = include_str!("kiosk.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        let confirm = body.find("display_manager_will_be_disabled(a.mode").expect("setup must gate the disable");
        let disable = body.find("sudo systemctl disable --now display-manager.service").unwrap();
        let first_write = body.find("// 1. the user").unwrap();
        assert!(confirm < first_write && first_write < disable, "the confirm must precede every write");
        assert!(parse_setup(&["--url".into(), "https://c.t.ts.net".into(), "--mode".into(), "shared".into(), "-y".into()]).unwrap().yes);
    }
}
