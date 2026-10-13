// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The `tailscale serve` mapping that fronts the gateway on the tailnet:
//! `/` → the dashboard, and the three MCP doors. ONE implementation,
//! called by `noo onboard` and `noo controller promote` — promote used to
//! carry its own copy that discarded both exit statuses and printed
//! "rebound" from intent rather than outcome (host8, cutover 2026-09-01:
//! `tailscale serve status` said "No serve config" for days).
//!
//! `tailscale serve --set-path=P target` strips P before proxying, so a
//! door at `/mcp/user` on the ts.net host is `--set-path=/mcp/user
//! https://ip:8080/mcp/user`. A named instance mounts
//! everything under `/<instance>`.
use std::process::Command;

/// What to map: the gateway's tailnet IP and port, and the instance
/// prefix ("" for the default instance).
pub struct Plan {
    pub ip: String,
    pub gw_port: u32,
    pub instance: String,
}

/// The MCP doors the gateway serves on :8080, as (ts.net path suffix,
/// gateway path) — the same two names on both sides. The ts.net `/mcp`
/// path (an alias that fronted the gateway's `/mcp/external`, itself an
/// alias) is not written any more as of stack-v0.2.40: `tailscale serve`
/// never removes a path it is not told about, so a controller onboarded
/// earlier keeps a stale `/mcp` proxying to a 404 until the operator runs
/// `tailscale serve --https=443 --set-path=/mcp off`.
pub const DOORS: &[(&str, &str)] = &[
    ("/mcp/user", "/mcp/user"),
    ("/mcp/operator", "/mcp/operator"),
];

impl Plan {
    pub fn root_path(&self) -> String {
        if self.instance.is_empty() { String::new() } else { format!("/{}", self.instance) }
    }

    fn backend(&self) -> String {
        format!("https://{}:{}", self.ip, self.gw_port)
    }

    /// The ts.net path of each door, in DOORS order.
    pub fn door_paths(&self) -> Vec<String> {
        let root = self.root_path();
        DOORS.iter().map(|(p, _)| format!("{root}{p}")).collect()
    }

    /// The `tailscale …` argument vectors, root first.
    pub fn commands(&self) -> Vec<Vec<String>> {
        let backend = self.backend();
        let root = self.root_path();
        let mut out = Vec::with_capacity(1 + DOORS.len());
        let mut first = vec!["serve".to_string(), "--bg".to_string()];
        if !root.is_empty() {
            first.push(format!("--set-path={root}"));
        }
        first.push(backend.clone());
        out.push(first);
        for (path, target) in DOORS {
            out.push(vec![
                "serve".to_string(),
                "--bg".to_string(),
                format!("--set-path={root}{path}"),
                format!("{backend}{target}"),
            ]);
        }
        out
    }

    /// The same, as lines an operator can paste when we could not write them.
    pub fn manual_lines(&self) -> Vec<String> {
        self.commands().into_iter().map(|c| format!("sudo tailscale {}", c.join(" "))).collect()
    }
}

pub struct Applied {
    /// `tailscale set --operator=$USER` was granted on the way (one-time
    /// tailscaled state; every later run writes serve config without root).
    pub granted_operator: bool,
}

pub struct Failure {
    /// The `tailscale …` line that failed.
    pub command: String,
    /// Its stderr, trimmed.
    pub detail: String,
}

fn looks_like_permission(detail: &str) -> bool {
    let d = detail.to_ascii_lowercase();
    d.contains("operator") || d.contains("root") || d.contains("permission") || d.contains("denied")
}

fn run_ts(args: &[String]) -> Result<(), Failure> {
    let out = Command::new("tailscale").args(args).output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(Failure {
            command: format!("tailscale {}", args.join(" ")),
            detail: String::from_utf8_lossy(&o.stderr).trim().to_string(),
        }),
        Err(e) => Err(Failure { command: format!("tailscale {}", args.join(" ")), detail: e.to_string() }),
    }
}

/// Grant the invoking user tailnet-operator via sudo (interactive sudo
/// may prompt on the tty; `non_interactive` uses `sudo -n` so a host
/// without passwordless sudo degrades to the manual hint, never a hang).
fn try_grant_operator(non_interactive: bool) -> bool {
    let Ok(user) = std::env::var("USER") else { return false };
    let mut grant = Command::new("sudo");
    if non_interactive {
        grant.arg("-n");
    }
    grant.args(["tailscale", "set", &format!("--operator={user}")]);
    grant.status().map(|s| s.success()).unwrap_or(false)
}

/// Write every mapping in the plan, checking each exit status. A
/// permission failure triggers ONE operator grant + retry; anything else
/// is returned as the failure it is.
pub fn apply(plan: &Plan, non_interactive: bool) -> Result<Applied, Failure> {
    apply_commands(plan.commands(), non_interactive)
}

fn apply_commands(cmds: Vec<Vec<String>>, non_interactive: bool) -> Result<Applied, Failure> {
    let mut granted = false;
    for cmd in cmds {
        let mut r = run_ts(&cmd);
        if let Err(f) = &r {
            if !granted && looks_like_permission(&f.detail) && try_grant_operator(non_interactive) {
                granted = true;
                r = run_ts(&cmd);
            }
        }
        r?;
    }
    Ok(Applied { granted_operator: granted })
}

/// This controller's tailnet IPv4, or None when tailscale cannot say.
pub fn tailnet_ip() -> Option<String> {
    let out = Command::new("tailscale").args(["ip", "-4"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let ip = String::from_utf8_lossy(&out.stdout).lines().next()?.trim().to_string();
    if ip.is_empty() { None } else { Some(ip) }
}

/// Re-assert the serve mapping after a controller's stack comes up, so a
/// box that lost it gets it back without an operator noticing first.
///
/// The mapping was only ever WRITTEN by `noo onboard` and `noo controller
/// promote`. When the duplicate implementation in promote silently wrote
/// nothing (this module's header), the controller ran for days with every
/// container green, `noo upgrade --stack` reporting a healthy gateway, and
/// the dashboard plus all three MCP doors unreachable on the tailnet —
/// because nothing re-asserted it and nothing on the upgrade path looked.
/// A client forced onto the `:8080` URL then meets the cluster CA, which is
/// its own class of failure a long way from the cause.
///
/// Safe to call on every start: `apply` runs `tailscale` directly and only
/// reaches for sudo on a permission error, with `-n` here, so a host
/// without passwordless sudo prints the manual lines rather than hanging.
/// Once the one-time operator grant exists, no root is involved at all.
/// Never fails its caller — a front door that could not be rebuilt is a
/// warning on a roll that otherwise worked.
pub fn ensure_fronted(gw_port: u32, instance: &str) {
    if crate::role::detect().controller.is_none() {
        return; // a worker fronts nothing
    }
    match status(gw_port) {
        Status::Mapped { fronts_gateway: true, .. } => return, // already correct
        Status::Unknown(_) => return, // no tailscale, or it cannot say — not our call
        Status::NotMapped | Status::Mapped { .. } => {}
    }
    let Some(ip) = tailnet_ip() else { return };
    let plan = Plan { ip, gw_port, instance: instance.to_string() };
    match apply(&plan, true) {
        Ok(applied) => {
            crate::ui::done("tailnet serve mapping restored — the dashboard and MCP doors are fronted again");
            if applied.granted_operator {
                println!("{}", crate::ui::note("granted tailscale operator to this user (one-time)"));
            }
        }
        Err(f) => {
            crate::ui::warned(&format!(
                "tailnet serve has no mapping and could not be written (`{}`: {}) —                  the dashboard and MCP doors are not fronted on the tailnet",
                f.command, f.detail));
            println!("{}", crate::ui::hint("noo controller promote"));
        }
    }
}

/// This machine's MagicDNS name (`<host>.<tailnet>.ts.net`), without the
/// trailing dot, or None when tailscale can't say.
pub fn magic_dns_name() -> Option<String> {
    let out = Command::new("tailscale").args(["status", "--json"]).output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    let d = v["Self"]["DNSName"].as_str()?.trim_end_matches('.').to_string();
    if d.is_empty() { None } else { Some(d) }
}

/// The front door's URLs for a name and instance, in the order an operator
/// wants them. Pure: the shapes are what the tests pin.
pub fn front_door_urls_for(dns: &str, instance: &str) -> Vec<(&'static str, String)> {
    let plan = Plan { ip: String::new(), gw_port: 0, instance: instance.to_string() };
    let root = plan.root_path();
    let mut out = vec![("Dashboard", format!("https://{dns}{root}"))];
    for (i, path) in plan.door_paths().into_iter().enumerate() {
        let label = match DOORS[i].0 {
            "/mcp/user" => "MCP (user door)",
            "/mcp/operator" => "MCP (operator door)",
            _ => "MCP",
        };
        out.push((label, format!("https://{dns}{path}")));
    }
    out
}

/// The URLs this controller answers on over the tailnet — or None when the
/// serve mapping does not front the gateway, because then every one of
/// them is a dead link. Onboarding printed the dashboard URL without that
/// check, and on a controller whose mapping had never been written it
/// handed out an address on a closed port.
pub fn front_door_urls(gw_port: u32, instance: &str) -> Option<Vec<(&'static str, String)>> {
    match status(gw_port) {
        Status::Mapped { fronts_gateway: true, .. } => {}
        _ => return None,
    }
    Some(front_door_urls_for(&magic_dns_name()?, instance))
}

/// Say where this controller lives on the tailnet. Printed after a start
/// or a roll, and by `noo stack status`, so the answer to "what's my URL"
/// is never only in onboarding's scrollback. Silent on a worker and when
/// the door isn't fronted (`ensure_fronted` and `stack status` speak to
/// that case).
pub fn print_front_door(gw_port: u32, instance: &str) {
    if crate::role::detect().controller.is_none() {
        return;
    }
    let Some(urls) = front_door_urls(gw_port, instance) else { return };
    println!();
    println!("{}", crate::ui::status_line(crate::ui::Glyph::Ok, "on your tailnet"));
    let w = urls.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, url) in urls {
        println!("    {label:<w$}  {url}");
    }
}

// ── Grafana's own origin ────────────────────────────────────────────────
//
// Grafana stays on its OWN origin, `https://<tailnet-name>:<3000+offset>`,
// apart from the console's (script isolation: a Grafana page must never
// share an origin with the console's token). Until this, a tailnet
// controller published Grafana straight on its tailnet IP with the
// cluster-CA leaf; a browser does not trust the cluster CA, and `ts.net` is
// HSTS-preloaded, so the certificate error could not be clicked through
// (host8, 2026-10-02: ERR_CERT_AUTHORITY_INVALID).
//
// Now `tailscale serve` listens on Grafana's port of the tailnet name,
// presenting the node's Let's Encrypt certificate, and proxies to
// `https://127.0.0.1:<port>`; once that entry is CONFIRMED, Grafana's port
// moves to loopback (`grafana_door::Door::settled`). Never before: a serve
// write that fails leaves the tailnet-IP publish in place, so the operator
// keeps a browser path, untrusted certificate and all.
//
// The hop behind serve is verified exactly the way the `/` mapping's hop to
// the gateway is: `https://`, checked by tailscaled against the OS trust
// store, which onboarding (and `noo security pki rotate-ca`) fills with the
// cluster CA and then restarts tailscaled. Grafana's leaf always carries
// the `127.0.0.1` IP SAN. Grafana keeps serving TLS with that leaf, and the
// gateway still reaches it over the compose network (`https://grafana:3000`).
//
// ADDITIVE ONLY. `tailscale serve --bg --https=<port> <target>` reads the
// whole ServeConfig, sets the web handler for `<host>:<port>` mount `/`, and
// writes the config back (cmd/tailscale/cli/serve_v2.go: GetServeConfig →
// SetWebHandler → SetServeConfig), so every other entry — the console's 443
// `/` and `/mcp/*`, anything the operator made — survives. It DOES silently
// replace a web handler already on that port and mount, so this module
// refuses to write when the port carries anything but our own entry
// ([`GrafanaServe::Elsewhere`]). Nothing here runs `serve reset` or `off`.

/// The proxy target `tailscale serve` hands Grafana's port to.
pub fn grafana_backend(port: u32) -> String {
    format!("https://127.0.0.1:{port}")
}

/// The `tailscale …` argument vector for Grafana's port: its own HTTPS
/// listener (`--https=<port>`), the whole path space, the local Grafana.
pub fn grafana_command(port: u32) -> Vec<String> {
    vec![
        "serve".to_string(),
        "--bg".to_string(),
        format!("--https={port}"),
        grafana_backend(port),
    ]
}

/// The line an operator runs by hand when noo could not write it.
pub fn grafana_manual_line(port: u32) -> String {
    format!("tailscale {}", grafana_command(port).join(" "))
}

/// Whether serve fronts Grafana's port right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrafanaServe {
    /// `<host>:<port>` `/` proxies to the local Grafana.
    Fronted,
    /// Nothing on that port.
    Absent,
    /// Something else is on that port (the operator's own entry, or TCP
    /// forwarding): what it is. Never overwritten.
    Elsewhere(String),
    /// tailscale absent, tailscaled down, or its output unparseable.
    Unknown(String),
}

/// Pure half of [`grafana_serve_status`]: read Grafana's port out of
/// tailscale's ServeConfig JSON.
pub fn parse_grafana_serve(text: &str, port: u32) -> GrafanaServe {
    let t = text.trim();
    if t.is_empty() || t.contains("No serve config") {
        return GrafanaServe::Absent;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else {
        return GrafanaServe::Unknown(format!("unparseable serve status: {}", t.chars().take(80).collect::<String>()));
    };
    let key = port.to_string();
    if let Some(tcp) = v.get("TCP").and_then(|t| t.get(&key)) {
        if let Some(fwd) = tcp.get("TCPForward").and_then(|f| f.as_str()).filter(|f| !f.is_empty()) {
            return GrafanaServe::Elsewhere(format!("TCP forwarding to {fwd}"));
        }
    }
    let suffix = format!(":{port}");
    let want = grafana_backend(port);
    let want_named = format!("https://localhost:{port}");
    let Some(web) = v.get("Web").and_then(|w| w.as_object()) else { return GrafanaServe::Absent };
    for (host, cfg) in web {
        if !host.ends_with(&suffix) {
            continue;
        }
        let handlers = cfg.get("Handlers").and_then(|h| h.as_object());
        let root = handlers.and_then(|h| h.get("/"));
        let proxy = root.and_then(|r| r.get("Proxy")).and_then(|p| p.as_str()).unwrap_or("").trim_end_matches('/');
        // Ours: `/` to the local Grafana, plus at most our own bookmark
        // redirect at `/login` (see [`grafana_login_command`]). Any other
        // path on the port is someone else's.
        let only_ours = handlers
            .map(|h| h.iter().all(|(path, hd)| path == "/" || (path == GRAFANA_LOGIN_MOUNT && is_our_login(hd, port))))
            .unwrap_or(false);
        if only_ours && (proxy == want || proxy == want_named) {
            return GrafanaServe::Fronted;
        }
        let what = match (proxy.is_empty(), handlers.map(|h| h.keys().cloned().collect::<Vec<_>>())) {
            (false, _) => proxy.to_string(),
            (true, Some(paths)) if !paths.is_empty() => format!("handlers at {}", paths.join(", ")),
            _ => "a handler that is not a proxy".to_string(),
        };
        return GrafanaServe::Elsewhere(what);
    }
    GrafanaServe::Absent
}

/// What serve says about Grafana's port on this machine.
pub fn grafana_serve_status(port: u32) -> GrafanaServe {
    match Command::new("tailscale").args(["serve", "status", "--json"]).output() {
        Ok(o) if o.status.success() => parse_grafana_serve(&String::from_utf8_lossy(&o.stdout), port),
        Ok(o) => GrafanaServe::Unknown(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => GrafanaServe::Unknown(e.to_string()),
    }
}

/// The commands that bring Grafana's port to [`GrafanaServe::Fronted`]:
/// none when it already is, and none when the port carries someone else's
/// entry (never overwritten). Absent or unreadable: the one Grafana-port
/// write; whether it took is decided by reading the status back.
pub fn grafana_serve_plan(current: &GrafanaServe, port: u32) -> Vec<Vec<String>> {
    match current {
        GrafanaServe::Fronted | GrafanaServe::Elsewhere(_) => vec![],
        GrafanaServe::Absent | GrafanaServe::Unknown(_) => vec![grafana_command(port)],
    }
}

/// How fronting Grafana's port went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fronting {
    /// It already was; nothing written.
    Already,
    /// Written now, and the status read back confirms it.
    Written,
}

/// Why Grafana's port is NOT confirmed fronted. Every case leaves the
/// tailnet-IP publish where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontError {
    /// The port carries an entry that is not ours; left untouched.
    Occupied(String),
    /// The write failed (tailscale absent, tailscaled down, no operator).
    Write(String),
    /// The write returned success but the status does not show the entry
    /// (or cannot be read).
    Unconfirmed(String),
}

impl FrontError {
    /// One sentence for a warning or a verify detail.
    pub fn say(&self, port: u32) -> String {
        match self {
            FrontError::Occupied(t) => format!("tailscale serve already sends :{port} to {t}, which noo leaves alone"),
            FrontError::Write(d) => format!("could not write the tailscale serve entry for :{port}: {d}"),
            FrontError::Unconfirmed(d) => format!("the tailscale serve entry for :{port} could not be confirmed: {d}"),
        }
    }
}

/// [`ensure_grafana_fronted`] with the status read and the `tailscale`
/// runner passed in, for tests: the runner sees every command issued.
pub fn ensure_grafana_fronted_with(
    port: u32,
    status: &dyn Fn() -> GrafanaServe,
    run: &mut dyn FnMut(&[String]) -> Result<(), Failure>,
) -> Result<Fronting, FrontError> {
    let before = status();
    if let GrafanaServe::Elsewhere(t) = &before {
        return Err(FrontError::Occupied(t.clone()));
    }
    let cmds = grafana_serve_plan(&before, port);
    if cmds.is_empty() {
        return Ok(Fronting::Already);
    }
    for c in &cmds {
        run(c).map_err(|f| FrontError::Write(format!("`{}` failed: {}", f.command, f.detail)))?;
    }
    match status() {
        GrafanaServe::Fronted => Ok(Fronting::Written),
        GrafanaServe::Elsewhere(t) => Err(FrontError::Unconfirmed(format!("the port now goes to {t}"))),
        GrafanaServe::Absent => Err(FrontError::Unconfirmed("serve status does not show it".into())),
        GrafanaServe::Unknown(e) => Err(FrontError::Unconfirmed(e)),
    }
}

/// Front Grafana's port with serve, additively and idempotently, and say
/// whether the entry is now CONFIRMED. A permission failure gets one
/// operator grant + retry, as for the console's mappings.
pub fn ensure_grafana_fronted(port: u32, non_interactive: bool) -> Result<Fronting, FrontError> {
    let mut granted = false;
    ensure_grafana_fronted_with(port, &|| grafana_serve_status(port), &mut |cmd| {
        let mut r = run_ts(cmd);
        if let Err(f) = &r {
            if !granted && looks_like_permission(&f.detail) && try_grant_operator(non_interactive) {
                granted = true;
                r = run_ts(cmd);
            }
        }
        r
    })
}

// ── A bookmark of Grafana's port leads somewhere ───────────────────────
//
// Grafana has no login of its own (grafana_door.rs): sign-in is only the
// console's "Open Grafana". A browser that reaches the port with no session
// — a bookmark, a typed URL, or a session that just expired — is sent by
// Grafana to `/login`, which renders a bare "Welcome to Grafana" with
// nothing to click (measured on 12.4.11: `/` and `/d/<uid>` answer 302
// `/login`; an expired session's SPA does a full-page load of
// `/login?redirectTo=…`). Grafana OSS has no setting that redirects its
// login page, but its `/logout` answers a 302 to `[auth]
// signout_redirect_url` for anyone, signed in or not (measured), and
// grafana.ini sets that to `NOO_GRAFANA_CONSOLE_URL`: the console's
// `#/observability?open=grafana`, whose Observe panel opens Grafana for
// the visitor once the console's own login is satisfied.
//
// So serve maps ONE more path on Grafana's port: `/login` → the local
// Grafana's `/logout`. Same rules as the `/` entry: additive (that mount
// only, `--set-path=/login`; serve_v2 keeps every other handler), never
// written over a handler that is not ours, confirmed by reading the status
// back. A proxy rather than a file or text handler on purpose: tailscaled
// refuses a path handler to an operator who cannot `sudo tailscale`, and a
// text handler cannot link. Nothing of the console's crosses to this origin:
// the visitor's browser leaves Grafana's origin for the console's.

/// The mount on Grafana's port that catches Grafana's own login redirect.
pub const GRAFANA_LOGIN_MOUNT: &str = "/login";

/// Where `/login` goes: the local Grafana's `/logout`, which answers 302
/// to `signout_redirect_url` (the console's Open Grafana).
pub fn grafana_login_backend(port: u32) -> String {
    format!("https://127.0.0.1:{port}/logout")
}

fn is_our_login(handler: &serde_json::Value, port: u32) -> bool {
    let p = handler.get("Proxy").and_then(|p| p.as_str()).unwrap_or("").trim_end_matches('/');
    p == grafana_login_backend(port) || p == format!("https://localhost:{port}/logout")
}

/// The `tailscale …` argument vector for the bookmark redirect: Grafana's
/// listener, the `/login` mount only, the local Grafana's `/logout`.
pub fn grafana_login_command(port: u32) -> Vec<String> {
    vec![
        "serve".to_string(),
        "--bg".to_string(),
        format!("--https={port}"),
        format!("--set-path={GRAFANA_LOGIN_MOUNT}"),
        grafana_login_backend(port),
    ]
}

/// The line an operator runs by hand when noo could not write it.
pub fn grafana_login_manual_line(port: u32) -> String {
    format!("tailscale {}", grafana_login_command(port).join(" "))
}

/// Whether Grafana's port carries the bookmark redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginRedirect {
    /// `/login` proxies to the local Grafana's `/logout`.
    Mapped,
    /// No `/login` on the port.
    Absent,
    /// `/login` is something else (left alone), or the port is not ours.
    Elsewhere(String),
    /// tailscale absent, tailscaled down, or its output unparseable.
    Unknown(String),
}

/// Pure half of [`grafana_login_status`].
pub fn parse_grafana_login(text: &str, port: u32) -> LoginRedirect {
    let t = text.trim();
    if t.is_empty() || t.contains("No serve config") {
        return LoginRedirect::Absent;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else {
        return LoginRedirect::Unknown(format!("unparseable serve status: {}", t.chars().take(80).collect::<String>()));
    };
    let suffix = format!(":{port}");
    let Some(web) = v.get("Web").and_then(|w| w.as_object()) else { return LoginRedirect::Absent };
    for (host, cfg) in web {
        if !host.ends_with(&suffix) {
            continue;
        }
        let Some(h) = cfg.get("Handlers").and_then(|h| h.get(GRAFANA_LOGIN_MOUNT)) else { return LoginRedirect::Absent };
        if is_our_login(h, port) {
            return LoginRedirect::Mapped;
        }
        let what = h.get("Proxy").and_then(|p| p.as_str()).map(str::to_string).unwrap_or_else(|| "a handler that is not ours".into());
        return LoginRedirect::Elsewhere(what);
    }
    LoginRedirect::Absent
}

/// What serve says about the bookmark redirect on this machine.
pub fn grafana_login_status(port: u32) -> LoginRedirect {
    match Command::new("tailscale").args(["serve", "status", "--json"]).output() {
        Ok(o) if o.status.success() => parse_grafana_login(&String::from_utf8_lossy(&o.stdout), port),
        Ok(o) => LoginRedirect::Unknown(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => LoginRedirect::Unknown(e.to_string()),
    }
}

/// [`ensure_grafana_login`] with the status read and the runner passed in.
/// Only ever called once `/` is CONFIRMED ours ([`GrafanaServe::Fronted`]).
pub fn ensure_grafana_login_with(
    port: u32,
    status: &dyn Fn() -> LoginRedirect,
    run: &mut dyn FnMut(&[String]) -> Result<(), Failure>,
) -> Result<Fronting, String> {
    match status() {
        LoginRedirect::Mapped => return Ok(Fronting::Already),
        LoginRedirect::Elsewhere(t) => {
            return Err(format!("tailscale serve already sends :{port}{GRAFANA_LOGIN_MOUNT} to {t}, which noo leaves alone"))
        }
        LoginRedirect::Absent | LoginRedirect::Unknown(_) => {}
    }
    run(&grafana_login_command(port)).map_err(|f| format!("`{}` failed: {}", f.command, f.detail))?;
    match status() {
        LoginRedirect::Mapped => Ok(Fronting::Written),
        LoginRedirect::Elsewhere(t) => Err(format!("the :{port}{GRAFANA_LOGIN_MOUNT} entry could not be confirmed: it now goes to {t}")),
        LoginRedirect::Absent => Err(format!("the :{port}{GRAFANA_LOGIN_MOUNT} entry could not be confirmed: serve status does not show it")),
        LoginRedirect::Unknown(e) => Err(format!("the :{port}{GRAFANA_LOGIN_MOUNT} entry could not be confirmed: {e}")),
    }
}

/// Map `/login` on Grafana's port to the console (additively,
/// idempotently), and say whether it is CONFIRMED.
pub fn ensure_grafana_login(port: u32, non_interactive: bool) -> Result<Fronting, String> {
    let mut granted = false;
    ensure_grafana_login_with(port, &|| grafana_login_status(port), &mut |cmd| {
        let mut r = run_ts(cmd);
        if let Err(f) = &r {
            if !granted && looks_like_permission(&f.detail) && try_grant_operator(non_interactive) {
                granted = true;
                r = run_ts(cmd);
            }
        }
        r
    })
}

/// The console URL a bookmark of Grafana's port is sent to: the console's
/// front door (instance prefix included) with the Observe panel asked to
/// open Grafana. Pure, from the same derivation as the printed URLs.
pub fn console_open_grafana_url(dns: &str, instance: &str) -> String {
    let base = front_door_urls_for(dns.trim().trim_end_matches('.'), instance)[0].1.clone();
    format!("{base}/#/observability?open=grafana")
}

/// What `tailscale serve status --json` says is mapped right now.
pub enum Status {
    /// `{}` — nothing is served.
    NotMapped,
    /// Mapped paths (every host's handler keys) and whether any of them
    /// proxies to the gateway port.
    Mapped { paths: Vec<String>, fronts_gateway: bool },
    /// tailscale absent, or its output unparseable.
    Unknown(String),
}

pub fn status(gw_port: u32) -> Status {
    match Command::new("tailscale").args(["serve", "status", "--json"]).output() {
        Ok(o) if o.status.success() => parse_status(&String::from_utf8_lossy(&o.stdout), gw_port),
        Ok(o) => Status::Unknown(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Status::Unknown(e.to_string()),
    }
}

/// Pure half of `status`, for tests. The JSON is tailscale's ServeConfig:
/// `{"Web":{"<host>:443":{"Handlers":{"/":{"Proxy":"https://…:8080"},…}}}}`.
pub fn parse_status(text: &str, gw_port: u32) -> Status {
    let t = text.trim();
    if t.is_empty() || t.contains("No serve config") {
        return Status::NotMapped;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(t) else {
        return Status::Unknown(format!("unparseable serve status: {}", t.chars().take(80).collect::<String>()));
    };
    let mut paths = Vec::new();
    let mut fronts = false;
    let port = format!(":{gw_port}");
    if let Some(web) = v.get("Web").and_then(|w| w.as_object()) {
        for host in web.values() {
            if let Some(h) = host.get("Handlers").and_then(|h| h.as_object()) {
                for (path, handler) in h {
                    paths.push(path.clone());
                    if handler.get("Proxy").and_then(|p| p.as_str()).is_some_and(|p| p.contains(&port)) {
                        fronts = true;
                    }
                }
            }
        }
    }
    if paths.is_empty() {
        Status::NotMapped
    } else {
        paths.sort();
        Status::Mapped { paths, fronts_gateway: fronts }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_instance_maps_root_and_the_two_doors() {
        let p = Plan { ip: "100.64.0.9".into(), gw_port: 8080, instance: String::new() };
        let c = p.commands();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0], vec!["serve", "--bg", "https://100.64.0.9:8080"]);
        assert_eq!(c[1], vec!["serve", "--bg", "--set-path=/mcp/user", "https://100.64.0.9:8080/mcp/user"]);
        assert_eq!(c[2], vec!["serve", "--bg", "--set-path=/mcp/operator", "https://100.64.0.9:8080/mcp/operator"]);
        // No alias path: the plan writes only names the gateway serves.
        assert!(c.iter().all(|v| !v.iter().any(|a| a == "--set-path=/mcp")), "the /mcp alias must not be written");
        assert!(p.manual_lines().iter().all(|l| l.starts_with("sudo tailscale serve --bg ")));
    }

    #[test]
    fn named_instance_mounts_under_its_prefix_with_the_offset_port() {
        let p = Plan { ip: "100.64.0.9".into(), gw_port: 8180, instance: "obtest".into() };
        let c = p.commands();
        assert_eq!(c[0], vec!["serve", "--bg", "--set-path=/obtest", "https://100.64.0.9:8180"]);
        assert_eq!(c[1][2], "--set-path=/obtest/mcp/user");
        assert_eq!(c[2][3], "https://100.64.0.9:8180/mcp/operator");
        assert_eq!(p.door_paths(), vec!["/obtest/mcp/user", "/obtest/mcp/operator"]);
    }

    /// `ensure_fronted` decides from `status` alone, so the decision is
    /// worth pinning even though the call itself shells out: it must act on
    /// the two broken shapes, stay silent when the mapping is already right,
    /// and do nothing when tailscale cannot answer — an unreadable status is
    /// not evidence the door is missing, and rewriting on it would fight
    /// whatever else is managing the config.
    #[test]
    fn a_missing_or_misdirected_mapping_is_the_only_thing_worth_rewriting() {
        let act = |s: &Status| matches!(s, Status::NotMapped | Status::Mapped { fronts_gateway: false, .. });
        assert!(act(&Status::NotMapped), "nothing served — this is the host8 case");
        assert!(act(&Status::Mapped { fronts_gateway: false, paths: vec!["/".into()] }),
            "mapped at something that is not the gateway");
        assert!(!act(&Status::Mapped { fronts_gateway: true, paths: vec!["/".into()] }),
            "already correct — say nothing");
        assert!(!act(&Status::Unknown("no tailscale".into())),
            "cannot say is not the same as not mapped");
    }

    /// The roll must re-assert the mapping. Written against the source so a
    /// refactor that drops the call is caught: the whole defect was that
    /// nothing on the upgrade path looked at the front door.
    #[test]
    fn the_stack_roll_reasserts_the_front_door() {
        let src = include_str!("commands/upgrade.rs");
        let code = &src[..src.find("#[cfg(test)]").unwrap_or(src.len())];
        assert!(code.contains("ensure_fronted("),
            "a successful stack roll must re-assert the tailnet serve mapping");
        assert!(code.contains("port_offset()") && code.contains("instance()"),
            "and must use the instance-aware port and prefix, not the default shape");
    }

    /// What an operator is told their address is. Default instance at the
    /// root; a named instance under its prefix, both doors beneath it.
    #[test]
    fn the_front_door_urls_are_the_ones_the_mapping_serves() {
        let d = front_door_urls_for("noo-controller.example.ts.net", "");
        assert_eq!(d[0], ("Dashboard", "https://noo-controller.example.ts.net".to_string()));
        assert_eq!(d[1].1, "https://noo-controller.example.ts.net/mcp/user");
        assert_eq!(d[2].1, "https://noo-controller.example.ts.net/mcp/operator");
        let n = front_door_urls_for("noo-controller.example.ts.net", "obtest");
        assert_eq!(n[0].1, "https://noo-controller.example.ts.net/obtest");
        assert_eq!(n[1].1, "https://noo-controller.example.ts.net/obtest/mcp/user");
        // The URLs are derived from DOORS, not restated — a new door appears here.
        assert_eq!(d.len(), 1 + DOORS.len());
    }

    #[test]
    fn status_parses_empty_text_and_a_real_config() {
        assert!(matches!(parse_status("{}", 8080), Status::NotMapped));
        assert!(matches!(parse_status("No serve config\n", 8080), Status::NotMapped));
        let cfg = r#"{"Web":{"noo-controller.example.ts.net:443":{"Handlers":{
            "/":{"Proxy":"https://100.64.0.9:8080"},
            "/mcp/user":{"Proxy":"https://100.64.0.9:8080/mcp/user"}}}}}"#;
        match parse_status(cfg, 8080) {
            Status::Mapped { paths, fronts_gateway } => {
                assert_eq!(paths, vec!["/", "/mcp/user"]);
                assert!(fronts_gateway);
            }
            _ => panic!("expected Mapped"),
        }
        match parse_status(cfg, 9090) {
            Status::Mapped { fronts_gateway, .. } => assert!(!fronts_gateway, "a different port is not the gateway"),
            _ => panic!("expected Mapped"),
        }
        assert!(matches!(parse_status("garbage", 8080), Status::Unknown(_)));
    }

    /// The live host8 ServeConfig (2026-10-02) plus Grafana's port.
    const LIVE_WITH_GRAFANA: &str = r#"{"TCP":{"443":{"HTTPS":true},"3000":{"HTTPS":true}},"Web":{
        "noo-controller.example.ts.net:443":{"Handlers":{
            "/":{"Proxy":"https://100.64.0.12:8080"},
            "/mcp/user":{"Proxy":"https://100.64.0.12:8080/mcp/user"}}},
        "noo-controller.example.ts.net:3000":{"Handlers":{"/":{"Proxy":"https://127.0.0.1:3000"}}}}}"#;

    /// The console's 443 entries plus an operator's own entry on :8443.
    const LIVE_PLUS_OPERATOR: &str = r#"{"TCP":{"443":{"HTTPS":true},"8443":{"HTTPS":true}},"Web":{
        "noo-controller.example.ts.net:443":{"Handlers":{
            "/":{"Proxy":"https://100.64.0.12:8080"},
            "/mcp/user":{"Proxy":"https://100.64.0.12:8080/mcp/user"},
            "/mcp/operator":{"Proxy":"https://100.64.0.12:8080/mcp/operator"}}},
        "noo-controller.example.ts.net:8443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:9999"}}}}}"#;

    fn ok_run(log: &mut Vec<Vec<String>>) -> impl FnMut(&[String]) -> Result<(), Failure> + '_ {
        move |c: &[String]| {
            log.push(c.to_vec());
            Ok(())
        }
    }

    #[test]
    fn grafana_gets_its_own_https_port_proxied_to_loopback() {
        assert_eq!(grafana_command(3000), vec!["serve", "--bg", "--https=3000", "https://127.0.0.1:3000"]);
        // The instance offset reaches both the listener and the target.
        assert_eq!(grafana_command(3100), vec!["serve", "--bg", "--https=3100", "https://127.0.0.1:3100"]);
        // Verified TLS to the backend, exactly like the `/` mapping.
        assert!(grafana_command(3000).iter().all(|a| !a.contains("insecure") && !a.starts_with("http://")));
        assert_eq!(grafana_manual_line(3000), "tailscale serve --bg --https=3000 https://127.0.0.1:3000");
    }

    /// ADDITIVE ONLY: against a config holding the console's 443 `/` and
    /// `/mcp/*` plus an operator's entry on another port, the only command
    /// issued names Grafana's port — no reset, no `off`, no 443, no 8443.
    #[test]
    fn the_grafana_write_touches_only_the_grafana_port() {
        let mut log = Vec::new();
        let reads = std::cell::Cell::new(0);
        let status = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                parse_grafana_serve(LIVE_PLUS_OPERATOR, 3000)
            } else {
                GrafanaServe::Fronted
            }
        };
        let got = ensure_grafana_fronted_with(3000, &status, &mut ok_run(&mut log));
        assert_eq!(got, Ok(Fronting::Written));
        assert_eq!(log, vec![grafana_command(3000)]);
        for c in &log {
            assert!(c.iter().any(|a| a == "--https=3000"), "{c:?}");
            for bad in ["reset", "off", "--https=443", "--https=8443", "--set-path=/", "--set-path=/mcp/user"] {
                assert!(!c.iter().any(|a| a == bad), "{bad} in {c:?}");
            }
        }
        // The console's own reading of that config is untouched by Grafana's port.
        assert!(matches!(parse_status(LIVE_PLUS_OPERATOR, 8080), Status::Mapped { fronts_gateway: true, .. }));
    }

    /// A port the operator (or anything else) already uses is never
    /// overwritten: no command, an Occupied error that names it.
    #[test]
    fn an_operator_entry_on_the_grafana_port_is_left_alone() {
        let theirs = LIVE_PLUS_OPERATOR.replace(":8443", ":3000").replace("\"8443\"", "\"3000\"");
        let st = parse_grafana_serve(&theirs, 3000);
        assert_eq!(st, GrafanaServe::Elsewhere("http://127.0.0.1:9999".into()));
        let mut log = Vec::new();
        let got = ensure_grafana_fronted_with(3000, &|| st.clone(), &mut ok_run(&mut log));
        assert_eq!(got, Err(FrontError::Occupied("http://127.0.0.1:9999".into())));
        assert!(log.is_empty(), "nothing may be written over the operator's entry: {log:?}");
        // Our proxy plus an extra path of theirs is theirs too.
        let mixed = LIVE_WITH_GRAFANA.replace(
            r#""/":{"Proxy":"https://127.0.0.1:3000"}"#,
            r#""/":{"Proxy":"https://127.0.0.1:3000"},"/x":{"Proxy":"http://127.0.0.1:1"}"#,
        );
        assert!(matches!(parse_grafana_serve(&mixed, 3000), GrafanaServe::Elsewhere(_)));
        // TCP forwarding on the port is theirs.
        let tcp = r#"{"TCP":{"3000":{"TCPForward":"127.0.0.1:5432"}}}"#;
        assert_eq!(parse_grafana_serve(tcp, 3000), GrafanaServe::Elsewhere("TCP forwarding to 127.0.0.1:5432".into()));
    }

    /// A second run on a fronted port writes nothing.
    #[test]
    fn the_grafana_serve_entry_is_idempotent() {
        let live = parse_grafana_serve(LIVE_WITH_GRAFANA, 3000);
        assert_eq!(live, GrafanaServe::Fronted);
        assert!(grafana_serve_plan(&live, 3000).is_empty());
        let mut log = Vec::new();
        assert_eq!(ensure_grafana_fronted_with(3000, &|| GrafanaServe::Fronted, &mut ok_run(&mut log)), Ok(Fronting::Already));
        assert!(log.is_empty());
        // Today's host8: the console is fronted, Grafana's port is not.
        assert_eq!(parse_grafana_serve(LIVE_PLUS_OPERATOR, 3000), GrafanaServe::Absent);
        assert_eq!(parse_grafana_serve("{}", 3000), GrafanaServe::Absent);
        // Another instance's port is not this one's.
        assert_eq!(parse_grafana_serve(LIVE_WITH_GRAFANA, 3100), GrafanaServe::Absent);
        assert!(matches!(parse_grafana_serve("garbage", 3000), GrafanaServe::Unknown(_)));
    }

    /// No tailscale / tailscaled down: the write fails or cannot be read
    /// back, and the answer is an error, never a confirmation.
    #[test]
    fn a_failed_or_unconfirmed_write_is_never_confirmed() {
        let down = || GrafanaServe::Unknown("No such file or directory (os error 2)".into());
        let mut fail = |c: &[String]| Err(Failure { command: format!("tailscale {}", c.join(" ")), detail: "not found".into() });
        assert!(matches!(ensure_grafana_fronted_with(3000, &down, &mut fail), Err(FrontError::Write(_))));
        let mut log = Vec::new();
        assert!(matches!(ensure_grafana_fronted_with(3000, &down, &mut ok_run(&mut log)), Err(FrontError::Unconfirmed(_))));
        let mut log = Vec::new();
        assert!(matches!(
            ensure_grafana_fronted_with(3000, &|| GrafanaServe::Absent, &mut ok_run(&mut log)),
            Err(FrontError::Unconfirmed(_))
        ));
    }

    #[test]
    fn permission_failures_are_recognised_by_tailscale_wording() {
        assert!(looks_like_permission("Access denied: serve config denied"));
        assert!(looks_like_permission("tailscale serve requires root or the operator"));
        assert!(!looks_like_permission("invalid port"));
    }

    /// The live host8 ServeConfig (2026-10-03) once the bookmark redirect
    /// is on Grafana's port.
    const LIVE_WITH_LOGIN: &str = r#"{"TCP":{"443":{"HTTPS":true},"3000":{"HTTPS":true}},"Web":{
        "noo-controller.example.ts.net:443":{"Handlers":{
            "/":{"Proxy":"https://100.64.0.12:8080"},
            "/mcp/user":{"Proxy":"https://100.64.0.12:8080/mcp/user"},
            "/mcp/operator":{"Proxy":"https://100.64.0.12:8080/mcp/operator"}}},
        "noo-controller.example.ts.net:3000":{"Handlers":{
            "/":{"Proxy":"https://127.0.0.1:3000"},
            "/login":{"Proxy":"https://127.0.0.1:3000/logout"}}}}}"#;

    #[test]
    fn the_bookmark_redirect_is_one_more_path_on_grafanas_port() {
        assert_eq!(
            grafana_login_command(3000),
            vec!["serve", "--bg", "--https=3000", "--set-path=/login", "https://127.0.0.1:3000/logout"]
        );
        assert_eq!(grafana_login_command(3100)[4], "https://127.0.0.1:3100/logout");
        assert!(grafana_login_command(3000).iter().all(|a| !a.contains("insecure") && !a.starts_with("http://")));
        // Our `/login` beside our `/` is still ours: Fronted, and Mapped.
        assert_eq!(parse_grafana_serve(LIVE_WITH_LOGIN, 3000), GrafanaServe::Fronted);
        assert_eq!(parse_grafana_login(LIVE_WITH_LOGIN, 3000), LoginRedirect::Mapped);
        // Before it: Fronted, and Absent.
        assert_eq!(parse_grafana_login(LIVE_WITH_GRAFANA, 3000), LoginRedirect::Absent);
        assert_eq!(parse_grafana_login("{}", 3000), LoginRedirect::Absent);
        // The console's own reading of the config is untouched by it.
        assert!(matches!(parse_status(LIVE_WITH_LOGIN, 8080), Status::Mapped { fronts_gateway: true, .. }));
        // Someone else's `/login` makes the port someone else's.
        let theirs = LIVE_WITH_LOGIN.replace("https://127.0.0.1:3000/logout", "http://127.0.0.1:7777");
        assert!(matches!(parse_grafana_serve(&theirs, 3000), GrafanaServe::Elsewhere(_)));
        assert_eq!(parse_grafana_login(&theirs, 3000), LoginRedirect::Elsewhere("http://127.0.0.1:7777".into()));
        assert!(matches!(parse_grafana_login("garbage", 3000), LoginRedirect::Unknown(_)));
    }

    /// ADDITIVE ONLY, as for `/`: the one command names Grafana's port and
    /// the `/login` mount — no reset, no `off`, no other port or path.
    #[test]
    fn the_bookmark_write_touches_only_login_on_grafanas_port() {
        let mut log = Vec::new();
        let reads = std::cell::Cell::new(0);
        let status = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 { parse_grafana_login(LIVE_WITH_GRAFANA, 3000) } else { parse_grafana_login(LIVE_WITH_LOGIN, 3000) }
        };
        assert_eq!(ensure_grafana_login_with(3000, &status, &mut ok_run(&mut log)), Ok(Fronting::Written));
        assert_eq!(log, vec![grafana_login_command(3000)]);
        for c in &log {
            for bad in ["reset", "off", "--https=443", "--set-path=/", "--set-path=/mcp/user", "--set-path=/mcp/operator"] {
                assert!(!c.iter().any(|a| a == bad), "{bad} in {c:?}");
            }
        }
        // Idempotent.
        let mut log = Vec::new();
        assert_eq!(ensure_grafana_login_with(3000, &|| LoginRedirect::Mapped, &mut ok_run(&mut log)), Ok(Fronting::Already));
        assert!(log.is_empty());
        // Someone else's `/login`: never overwritten.
        let mut log = Vec::new();
        let r = ensure_grafana_login_with(3000, &|| LoginRedirect::Elsewhere("http://127.0.0.1:7777".into()), &mut ok_run(&mut log));
        assert!(r.unwrap_err().contains("leaves alone"));
        assert!(log.is_empty(), "nothing may be written over the operator's entry: {log:?}");
        // Written but not confirmed: an error, never a confirmation.
        let mut log = Vec::new();
        assert!(ensure_grafana_login_with(3000, &|| LoginRedirect::Absent, &mut ok_run(&mut log)).is_err());
        let mut fail = |c: &[String]| Err(Failure { command: format!("tailscale {}", c.join(" ")), detail: "not found".into() });
        assert!(ensure_grafana_login_with(3000, &|| LoginRedirect::Absent, &mut fail).unwrap_err().contains("failed"));
    }

    #[test]
    fn a_bookmark_goes_to_the_consoles_open_grafana() {
        assert_eq!(console_open_grafana_url("ctl.example.ts.net", ""), "https://ctl.example.ts.net/#/observability?open=grafana");
        assert_eq!(console_open_grafana_url("ctl.example.ts.net.", "obtest"), "https://ctl.example.ts.net/obtest/#/observability?open=grafana");
        assert_eq!(grafana_login_manual_line(3000), "tailscale serve --bg --https=3000 --set-path=/login https://127.0.0.1:3000/logout");
    }
}
