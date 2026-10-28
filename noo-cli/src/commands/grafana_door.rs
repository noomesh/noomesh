// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Grafana's door: where the browser reaches Grafana, which
//! interface its port is published on, and whether anything but a noomesh
//! account can log in.
//!
//! Single sign-on needs `GRAFANA_ROOT_URL`: compose hands
//! it to the gateway as `NOO_GRAFANA_URL`, and an empty one makes "Open
//! Grafana" answer 503. Nothing wrote it, so every onboarded controller had
//! SSO off until someone edited `.env` by hand. It is derived here, once,
//! from what the install already declares — `NOO_BIND_MODE`, the tailnet
//! identity and the port offset — and written by onboarding and by
//! `noo upgrade --stack` alike, so an existing install is repaired by the
//! roll with no step of its own.
//!
//! The door is one of two, never a third:
//! - **loopback** (`https://localhost:<port>`, published on 127.0.0.1) for
//!   `local`, `all`, a literal LAN address and a controller with no tailnet
//!   identity — unchanged since the security review. `all` puts the
//!   cluster plane on every interface; it does not put Grafana there. A
//!   browser on another machine reaches it only through a tunnel to the
//!   controller (`ssh -L`), which the verify row says.
//! - **the tailnet** (`https://<tailnet-name>:<port>`) for `tailnet`, or a
//!   literal `NOO_BIND_MODE` that is this box's tailnet address. `tailscale
//!   serve --https=<port>` answers on that name with the node's Let's
//!   Encrypt certificate and proxies to a loopback Grafana
//!   ([`crate::tailnet_serve::ensure_grafana_fronted`]). Grafana keeps its
//!   OWN origin — the console is `https://<tailnet-name>` on 443 — so a
//!   Grafana page never shares the console's origin. Until 2026-10-02 the
//!   port was published straight on the tailnet IP with the cluster-CA
//!   leaf, which no browser trusts; `ts.net` is HSTS-preloaded, so the
//!   error could not even be clicked through.
//!
//! FAIL-SAFE ORDER: the tailnet door starts on the tailnet IP (the old
//! publish, a browser path with an untrusted certificate) and moves to
//! loopback only once the serve entry is CONFIRMED ([`Door::settled`]). A
//! serve write that fails, a tailscaled that is down, or an operator entry
//! already on the port leaves the publish where it is.
//!
//! Grafana's own login is closed by `configs/grafana/grafana.ini`
//! (`disable_login`, `[auth.basic] enabled = false`); [`login_findings`]
//! reads that file, and `noo cluster verify --controller` FAILs the
//! `grafana door` row on any finding.

use std::path::Path;

use super::cluster_verify::{Check, Verdict};

/// The browser's URL for Grafana; compose passes it to the gateway as
/// `NOO_GRAFANA_URL` and to Grafana as `GF_SERVER_ROOT_URL`.
pub const ROOT_URL_KEY: &str = "GRAFANA_ROOT_URL";
/// The host address Grafana's port is published on.
pub const BIND_ADDR_KEY: &str = "NOO_GRAFANA_BIND_ADDR";
/// Where a bookmark of Grafana's port is sent: the console's Observe panel
/// with Open Grafana asked for. Compose hands it to Grafana, whose
/// grafana.ini makes it `[auth] signout_redirect_url`; serve's `/login` on
/// Grafana's port proxies to Grafana's `/logout`, which answers 302 there
/// (tailnet_serve.rs, "A bookmark of Grafana's port leads somewhere").
pub const CONSOLE_URL_KEY: &str = "NOO_GRAFANA_CONSOLE_URL";
/// Grafana's port before the instance offset (`lib-instance.sh`).
pub const BASE_PORT: u32 = 3000;
/// The verify row's name.
pub const ROW: &str = "grafana door";

/// Where the browser reaches Grafana and where its port is published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Door {
    pub root_url: String,
    pub bind_addr: String,
    /// The tailnet door: the port `tailscale serve` must front (the same
    /// port as the URL's). `None` on the loopback door.
    pub serve_port: Option<u32>,
}

impl Door {
    /// The door once fronting is known: a tailnet door whose serve entry is
    /// CONFIRMED publishes on loopback; otherwise it stays as declared (the
    /// tailnet IP), so a failed serve write never strands Grafana.
    pub fn settled(&self, serve_confirmed: bool) -> Door {
        let mut d = self.clone();
        if d.serve_port.is_some() && serve_confirmed {
            d.bind_addr = "127.0.0.1".into();
        }
        d
    }

    /// The host name in `root_url` (what Grafana's leaf must carry).
    pub fn host(&self) -> String {
        url_host(&self.root_url)
    }
}

fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or("");
    authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority).to_string()
}

/// 100.64.0.0/10, the range Tailscale assigns.
pub fn is_tailnet_ip(addr: &str) -> bool {
    match addr.trim().parse::<std::net::Ipv4Addr>() {
        Ok(ip) => {
            let o = ip.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        Err(_) => false,
    }
}

fn is_loopback(addr: &str) -> bool {
    let a = addr.trim().trim_start_matches('[').trim_end_matches(']');
    a == "localhost" || a.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// Why a published address is wider than Grafana's door, or `None` when
/// it is loopback or a tailnet address. An EMPTY value is not wide: compose
/// reads it as unset and publishes on its 127.0.0.1 default.
pub fn wide_bind(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.is_empty() || is_loopback(a) || is_tailnet_ip(a) {
        return None;
    }
    if matches!(a, "0.0.0.0" | "::" | "[::]") {
        return Some(format!("{a} (every interface)"));
    }
    Some(format!("{a} (neither loopback nor the tailnet)"))
}

/// The door this install declares. Pure: the caller supplies the bind
/// mode, the tailnet identity it has (empty when none) and the port.
pub fn door_for(bind_mode: &str, ts_dnsname: &str, ts_ip: &str, port: u32) -> Door {
    let mode = bind_mode.trim();
    let dns = ts_dnsname.trim().trim_end_matches('.');
    let tailnet_ip = if mode == "tailnet" {
        Some(ts_ip.trim())
    } else if is_tailnet_ip(mode) {
        Some(mode)
    } else {
        None
    };
    match tailnet_ip {
        // Declared on the tailnet IP; `settled(true)` moves it to loopback.
        Some(ip) if !dns.is_empty() && is_tailnet_ip(ip) => Door {
            root_url: format!("https://{dns}:{port}"),
            bind_addr: ip.to_string(),
            serve_port: Some(port),
        },
        _ => Door { root_url: format!("https://localhost:{port}"), bind_addr: "127.0.0.1".into(), serve_port: None },
    }
}

/// Whether a `NOO_BIND_MODE` asks for the tailnet door.
pub fn asks_for_tailnet(bind_mode: &str) -> bool {
    let m = bind_mode.trim();
    m == "tailnet" || is_tailnet_ip(m)
}

/// The published addresses that are a tailnet IP: Grafana's port answering
/// the tailnet directly, with the cluster-CA leaf no browser trusts.
pub fn tailnet_publishes(addrs: &[String]) -> Vec<String> {
    addrs.iter().filter(|a| is_tailnet_ip(a)).cloned().collect()
}

/// One `.env` write and the sentence that says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    pub key: &'static str,
    pub value: String,
    pub why: String,
}

/// What to write, given the current values. Empty = nothing to do.
///
/// - `GRAFANA_ROOT_URL` unset: SSO is off. Write the door — both keys, so
///   the URL and the published address name the same place.
/// - The published address wider than the door (`0.0.0.0`, a LAN IP):
///   put it back on the door, whatever the URL says.
/// - The published address a tailnet IP on a SETTLED tailnet door (serve
///   confirmed, so `door.bind_addr` is loopback): back on loopback, where
///   `tailscale serve` reaches it. Any other door leaves a tailnet IP alone:
///   an unconfirmed serve entry, or a non-tailnet mode where an operator
///   chose it (kept, as before).
///
/// A URL the operator set is kept: this fills a gap, it does not overrule.
pub fn plan(root_url: &str, bind_addr: &str, door: &Door) -> Vec<Repair> {
    let mut out = Vec::new();
    if root_url.trim().is_empty() {
        out.push(Repair {
            key: ROOT_URL_KEY,
            value: door.root_url.clone(),
            why: format!("Grafana single sign-on was off (no {ROOT_URL_KEY}) — set to {}", door.root_url),
        });
        if bind_addr.trim() != door.bind_addr {
            out.push(Repair {
                key: BIND_ADDR_KEY,
                value: door.bind_addr.clone(),
                why: format!("Grafana published on {} to match", door.bind_addr),
            });
        }
        return out;
    }
    if let Some(why) = wide_bind(bind_addr) {
        out.push(Repair {
            key: BIND_ADDR_KEY,
            value: door.bind_addr.clone(),
            why: format!("Grafana was published on {why} — moved to {}", door.bind_addr),
        });
    } else if door.serve_port.is_some() && is_loopback(&door.bind_addr) && is_tailnet_ip(bind_addr) {
        out.push(Repair {
            key: BIND_ADDR_KEY,
            value: door.bind_addr.clone(),
            why: format!(
                "Grafana was published straight on the tailnet ({}), where browsers refuse its certificate — moved to {} behind tailscale serve",
                bind_addr.trim(),
                door.bind_addr
            ),
        });
    }
    out
}

/// The `.env` write that gives a bookmark of the tailnet door somewhere to
/// go, or `None`. Only the tailnet door has one (the loopback door has no
/// serve in front of it, so Grafana's `/login` is Grafana's own). A value
/// already set is kept, like the root URL: this fills a gap.
pub fn console_plan(current: &str, door: &Door, instance: &str) -> Option<Repair> {
    door.serve_port?;
    if !current.trim().is_empty() {
        return None;
    }
    let url = crate::tailnet_serve::console_open_grafana_url(&door.host(), instance);
    Some(Repair {
        key: CONSOLE_URL_KEY,
        value: url.clone(),
        why: format!("a bookmark of {} now leads to the console's Open Grafana ({url})", door.root_url),
    })
}

/// `NOO_INSTANCE` as the instance prefix: "" for the default instance,
/// whichever spelling (`mesh`, `noomesh`) declares it.
pub fn canonical_instance(v: &str) -> String {
    let v = v.trim();
    if matches!(v, "" | "mesh" | "noomesh") { String::new() } else { v.to_string() }
}

/// The value compose will see: the process environment first (it outranks
/// `.env` in compose, and `ensure_repo_env` has loaded the store, the yaml
/// config and `.env` into it), then `.env`.
fn effective(env_path: &Path, key: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| crate::onboard::env::read_env_key(env_path, key))
}

/// This install's declared door, read from what is on disk and the live
/// tailnet identity.
pub fn declared_door(env_path: &Path) -> Door {
    let mode = effective(env_path, "NOO_BIND_MODE");
    let (dns, ip) = crate::onboard::steps::tailscale_identity().unwrap_or_default();
    door_for(&mode, &dns, &ip, BASE_PORT + crate::envfile::port_offset())
}

/// Apply [`plan`] to `.env` and to this process's environment. The process
/// half matters: the CLI loaded `.env` into its environment at startup, the
/// launcher child inherits it, and compose prefers the environment to
/// `.env` — so a stale empty value would outrank the one just written (the
/// NOO_IMAGE_TAG lesson in `upgrade_stack`). Returns the sentences to print;
/// an `Err` names the key that could not be written.
pub fn reconcile_env(env_path: &Path, door: &Door, instance: &str) -> Result<Vec<String>, String> {
    let mut repairs = plan(&effective(env_path, ROOT_URL_KEY), &effective(env_path, BIND_ADDR_KEY), door);
    repairs.extend(console_plan(&effective(env_path, CONSOLE_URL_KEY), door, instance));
    let mut said = Vec::new();
    for r in repairs {
        crate::onboard::env::update_env_key(env_path, r.key, &r.value)
            .map_err(|e| format!("could not write {} to {}: {e}", r.key, env_path.display()))?;
        std::env::set_var(r.key, &r.value);
        said.push(r.why);
    }
    Ok(said)
}

/// What [`reconcile_door`] did, for the caller to print.
#[derive(Debug)]
pub struct DoorReport {
    /// The door as written (settled).
    pub door: Door,
    /// The `.env` sentences, or the key that could not be written.
    pub said: Result<Vec<String>, String>,
    /// The serve outcome on the tailnet door; `None` on the loopback door.
    pub front: Option<(u32, Result<crate::tailnet_serve::Fronting, crate::tailnet_serve::FrontError>)>,
    /// The bookmark redirect (`/login` on Grafana's port), tried only once
    /// the `/` entry is confirmed; `None` otherwise.
    pub login: Option<Result<crate::tailnet_serve::Fronting, String>>,
}

impl DoorReport {
    /// The warning to print when the tailnet door is not fronted, naming
    /// the manual step. `None` when there is nothing to warn about.
    pub fn warning(&self) -> Option<String> {
        let (port, Err(e)) = self.front.as_ref()? else { return None };
        let still = if is_tailnet_ip(&self.door.bind_addr) {
            format!(
                "Grafana stays published on the tailnet IP {}, where browsers show a certificate warning",
                self.door.bind_addr
            )
        } else {
            "Grafana has NO browser path from other machines".to_string()
        };
        let step = match e {
            crate::tailnet_serve::FrontError::Occupied(_) => format!(
                "free :{port} in `tailscale serve status`, then re-run `noo upgrade --stack`"
            ),
            _ => format!(
                "run `{}` (tailscaled up, as root or the tailscale operator), then `noo upgrade --stack`",
                crate::tailnet_serve::grafana_manual_line(*port)
            ),
        };
        Some(format!("{} — {still}. To fix: {step}", e.say(*port)))
    }

    /// The warning when the bookmark redirect could not be written: Grafana
    /// works from the console, but a bookmark of its port shows a bare page.
    pub fn login_warning(&self) -> Option<String> {
        let Some(Err(e)) = &self.login else { return None };
        let port = self.front.as_ref().map(|(p, _)| *p).unwrap_or(BASE_PORT);
        Some(format!(
            "{e} — Open Grafana from the console still works, but a bookmark of {} shows Grafana's bare welcome page. \
             To fix: run `{}` (as root or the tailscale operator), then `noo upgrade --stack`",
            self.door.root_url,
            crate::tailnet_serve::grafana_login_manual_line(port)
        ))
    }
}

/// The door, end to end: front the tailnet door's port (additively, via
/// `front`), settle the door on the outcome, and write `.env`. Never fails
/// its caller: a failed serve write keeps the tailnet-IP publish and comes
/// back in the report.
pub fn reconcile_door(
    env_path: &Path,
    declared: &Door,
    instance: &str,
    front: &dyn Fn(u32) -> Result<crate::tailnet_serve::Fronting, crate::tailnet_serve::FrontError>,
    login: &dyn Fn(u32) -> Result<crate::tailnet_serve::Fronting, String>,
) -> DoorReport {
    let front = declared.serve_port.map(|port| (port, front(port)));
    let confirmed = matches!(front, Some((_, Ok(_))));
    let door = declared.settled(confirmed);
    let said = reconcile_env(env_path, &door, instance);
    // The bookmark redirect rides on a CONFIRMED `/` entry only (a second
    // path on the same port, never a reason to write the first), and only
    // once Grafana has somewhere to send it: with no console URL, Grafana's
    // `/logout` answers 302 `/login`, which serve would send back to
    // `/logout` — a redirect loop instead of a bare page (measured).
    let has_console = !effective(env_path, CONSOLE_URL_KEY).trim().is_empty();
    let login = match &front {
        Some((port, Ok(_))) if has_console => Some(login(*port)),
        Some((_, Ok(_))) => Some(Err(format!("{CONSOLE_URL_KEY} is not set, so /login was not mapped"))),
        _ => None,
    };
    DoorReport { door, said, front, login }
}

/// Re-issue Grafana's leaf when it does not name the door's host, so the
/// browser can verify `https://<tailnet-name>:<port>`. `Ok(false)` = it
/// already did (or there is no CA to issue from).
pub fn ensure_leaf_names_door(ca: &crate::pki::ClusterCa, door: &Door, hostname: &str, node_ip: &str) -> Result<bool, String> {
    let host = door.host();
    let crt = ca.dir.join("services").join("grafana").join("service.crt");
    if !ca.ca_exists() || host == "localhost" || !crt.is_file() {
        return Ok(false);
    }
    use crate::onboard::steps::NamesOutcome;
    // The door's host stands in for the tailnet name: one derivation and
    // one re-issue path for every service leaf.
    crate::onboard::steps::ensure_service_cert_names(ca, "grafana", hostname, node_ip, &host)
        .map(|o| matches!(o, NamesOutcome::Reissued { .. }))
}

/// A minimal INI read: `section.key` → value, lowercased keys, last wins.
fn ini_value(ini: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    let mut found = None;
    for line in ini.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.starts_with(';') || l.is_empty() {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current = s.trim().to_ascii_lowercase();
            continue;
        }
        if current != section {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            if k.trim().eq_ignore_ascii_case(key) {
                found = Some(v.trim().to_ascii_lowercase());
            }
        }
    }
    found
}

/// Every way `grafana.ini` leaves a login open other than a noomesh
/// account's token, or SSO itself off. Empty = closed. Grafana's defaults
/// are what an absent key means: `disable_login` false, basic auth ON.
pub fn login_findings(ini: &str) -> Vec<String> {
    let is = |section: &str, key: &str, want: &str, default: &str| {
        ini_value(ini, section, key).unwrap_or_else(|| default.to_string()) == want
    };
    let mut out = Vec::new();
    if !is("auth.jwt", "enabled", "true", "false") {
        out.push("[auth.jwt] is not enabled, so no noomesh account can log in".to_string());
    }
    if !is("auth", "disable_login", "true", "false") {
        out.push("[auth] disable_login is not true, so Grafana's own username/password login is on".to_string());
    }
    if !is("auth.basic", "enabled", "false", "true") {
        out.push("[auth.basic] is enabled, so the local admin password logs in over HTTP".to_string());
    }
    if is("auth.anonymous", "enabled", "true", "false") {
        out.push("[auth.anonymous] is enabled, so no login is needed at all".to_string());
    }
    out
}

/// Where Grafana's Prometheus and Loki data sources must point: the gateway, which holds a read-only account to the provisioned
/// dashboards' own queries. A read-only noomesh account is a Grafana
/// Viewer, and open-source Grafana answers a Viewer's own query against any
/// data source it can reach.
pub const GATEWAY_DS_URL: &str = "https://gateway:8080/api/grafana-ds/";

/// Every way the data sources let a Viewer's own query past the gateway.
/// `files` is (file name, contents) of `configs/grafana/datasources/*.yml`;
/// `ini` is `grafana.ini`. Empty = every Prometheus and Loki data source
/// dials the gateway, and Grafana tells it who is looking.
pub fn datasource_findings(files: &[(String, String)], ini: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = Vec::new();
    for (name, text) in files {
        let mut typ: Option<String> = None;
        let mut url: Option<String> = None;
        for line in text.lines() {
            let t = line.trim().trim_start_matches("- ").trim();
            if t.starts_with('#') {
                continue;
            }
            if let Some(v) = t.strip_prefix("type:") {
                typ = Some(v.trim().trim_matches(['"', '\'']).to_string());
            } else if let Some(v) = t.strip_prefix("url:") {
                url = Some(v.trim().trim_matches(['"', '\'']).to_string());
            }
            if let (Some(ty), Some(u)) = (&typ, &url) {
                if ty == "prometheus" || ty == "loki" {
                    seen.push(ty.clone());
                    let want = format!("{GATEWAY_DS_URL}{ty}");
                    if *u != want {
                        out.push(format!("{name}: the {ty} data source dials {u}, not the gateway ({want})"));
                    }
                }
                typ = None;
                url = None;
            }
        }
    }
    for ty in ["prometheus", "loki"] {
        if !seen.iter().any(|s| s == ty) {
            out.push(format!("no provisioned {ty} data source was found to check"));
        }
    }
    if ini_value(ini, "dataproxy", "send_user_header").as_deref() != Some("true") {
        out.push("[dataproxy] send_user_header is not true, so the gateway cannot tell who is looking".to_string());
    }
    if ini_value(ini, "public_dashboards", "enabled").as_deref() != Some("false") {
        out.push("[public_dashboards] is not off, so a shared dashboard can be read with no login".to_string());
    }
    out
}

/// Grafana's calls home, each as (section, key, the value that turns it
/// off, Grafana's default, what the default does). Grafana 12.4 makes every
/// one of these by default (`defaults.ini`); grafana.ini turns each off and
/// tests/test_grafana_sso_parity.py pins the same list.
pub const PHONE_HOME: &[(&str, &str, &str, &str, &str)] = &[
    ("analytics", "reporting_enabled", "false", "true", "sends usage counters to stats.grafana.org"),
    ("analytics", "check_for_updates", "false", "true", "asks grafana.com for new Grafana versions"),
    ("analytics", "check_for_plugin_updates", "false", "true", "asks grafana.com for new plugin versions"),
    ("analytics", "feedback_links_enabled", "false", "true", "links to Grafana Labs' feedback forms"),
    ("news", "news_feed_enabled", "false", "true", "loads Grafana Labs' news feed"),
    ("snapshots", "external_enabled", "false", "true", "offers publishing snapshots to snapshots.raintank.io"),
    ("security", "disable_gravatar", "true", "false", "loads profile pictures from gravatar.com"),
    ("plugins", "plugin_admin_enabled", "false", "true", "installs and updates plugins from grafana.com"),
    ("plugins", "public_key_retrieval_disabled", "true", "false", "fetches plugin signing keys from grafana.com"),
    ("plugins", "preinstall_disabled", "true", "false", "installs plugins from grafana.com at start"),
    ("plugins", "preinstall_auto_update", "false", "true", "updates preinstalled plugins from grafana.com at start"),
    ("cloud_migration", "enabled", "false", "true", "offers migrating to Grafana Cloud"),
];

/// Every way grafana.ini lets Grafana call home. Empty = it calls nobody.
/// An absent key is Grafana's default, which is ON for every one.
pub fn phone_home_findings(ini: &str) -> Vec<String> {
    let mut out: Vec<String> = PHONE_HOME
        .iter()
        .filter(|(sec, key, off, default, _)| ini_value(ini, sec, key).unwrap_or_else(|| default.to_string()) != *off)
        .map(|(sec, key, off, _, what)| format!("[{sec}] {key} is not {off}, so Grafana {what}"))
        .collect();
    // The backstop for the calls no switch turns off (the remote plugin
    // catalog behind Administration → Plugins, the angular-detection
    // patterns): grafana.com's API pointed at Grafana's own loopback.
    let api = ini_value(ini, "grafana_com", "api_url").unwrap_or_else(|| "https://grafana.com/api".into());
    let host = url_host(&api);
    if !is_loopback(&host) {
        out.push(format!("[grafana_com] api_url is {api}, so the plugin catalog and angular-detection patterns are fetched from it"));
    }
    out
}

/// What the verify row judges, gathered by [`gather`].
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// `GRAFANA_ROOT_URL` as compose will see it.
    pub root_url: String,
    /// The RUNNING gateway's `NOO_GRAFANA_URL`; `None` = could not read it.
    pub gateway_url: Option<String>,
    /// `configs/grafana/grafana.ini` from the running checkout.
    pub ini: Option<String>,
    /// `GF_AUTH_*` names in the running Grafana's environment: overrides
    /// that outrank `grafana.ini` (compose sets none).
    pub auth_env: Vec<String>,
    /// Host addresses Grafana's port is published on; `None` = not running.
    pub published: Option<Vec<String>>,
    /// `configs/grafana/datasources/*.yml` from the running checkout (what
    /// compose mounts into Grafana); `None` = could not read the directory.
    pub datasources: Option<Vec<(String, String)>>,
    /// Whether the RUNNING gateway grants read-only users Grafana Viewer:
    /// its compose declares `NOO_GRAFANA_DS_VIA_GATEWAY=1`.
    /// `None` = could not read the gateway's environment.
    pub viewer_grant: Option<bool>,
    /// The tailnet door's port and what `tailscale serve` says about it;
    /// `None` on the loopback door, where nothing is fronted.
    pub fronting: Option<(u32, crate::tailnet_serve::GrafanaServe)>,
    /// `NOO_BIND_MODE` asks for the tailnet door but tailscale could not
    /// name this box (no binary, tailscaled down), so the door could not
    /// be derived.
    pub tailnet_unresolved: bool,
    /// The bookmark redirect on the tailnet door: what serve says about
    /// `/login`, and the RUNNING Grafana's `NOO_GRAFANA_CONSOLE_URL`
    /// (`None` = could not read its environment). `None` on the loopback door.
    pub bookmark: Option<(crate::tailnet_serve::LoginRedirect, Option<String>)>,
}

/// The gateway's compose declaration that turns the read-only Viewer on
/// (`auth::GRAFANA_DS_GATE_ENV` in the gateway).
pub const VIEWER_GRANT_ENV: &str = "NOO_GRAFANA_DS_VIA_GATEWAY";

/// The `grafana door` row. FAIL, naming the fix, when SSO
/// is off, Grafana has a login of its own, or its port is published wider
/// than loopback or the tailnet.
pub fn door_check(f: &Facts) -> Check {
    let fail = |detail: String, remedy: &str| Check { name: ROW, verdict: Verdict::Fail, detail, remedy: Some(remedy.to_string()) };
    let root = f.root_url.trim().trim_end_matches('/');
    if root.is_empty() {
        return fail(
            format!("Grafana single sign-on is off: {ROOT_URL_KEY} is unset, so the console's Open Grafana answers 503"),
            "noo upgrade --stack   # derives GRAFANA_ROOT_URL and NOO_GRAFANA_BIND_ADDR from NOO_BIND_MODE and recreates the stack",
        );
    }
    if !root.starts_with("https://") {
        return fail(
            format!("{ROOT_URL_KEY}={root} is not https — Grafana serves TLS only, and the session token would travel in the clear"),
            "noo upgrade --stack   # after blanking GRAFANA_ROOT_URL in .env, so the roll derives an https one",
        );
    }
    if let Some(gw) = &f.gateway_url {
        if gw.trim().trim_end_matches('/') != root {
            return fail(
                format!(
                    "the running gateway sends browsers to '{}' but {ROOT_URL_KEY} is {root} — it predates the setting",
                    gw.trim()
                ),
                "noo stack restart --force",
            );
        }
    }
    let Some(ini) = &f.ini else {
        return Check {
            name: ROW,
            verdict: Verdict::Warn,
            detail: format!("SSO URL {root}; could not read configs/grafana/grafana.ini to confirm Grafana has no login of its own"),
            remedy: None,
        };
    };
    let findings = login_findings(ini);
    if !findings.is_empty() {
        return fail(
            format!("Grafana has a login besides noomesh accounts: {}", findings.join("; ")),
            "noo upgrade --stack   # lays the release's configs/grafana/grafana.ini back down and recreates Grafana",
        );
    }
    let home = phone_home_findings(ini);
    if !home.is_empty() {
        return fail(
            format!("Grafana calls home: {}", home.join("; ")),
            "noo upgrade --stack   # lays the release's configs/grafana/grafana.ini back down and recreates Grafana",
        );
    }
    if !f.auth_env.is_empty() {
        return fail(
            format!(
                "the running Grafana overrides grafana.ini's login settings with {} — compose sets none",
                f.auth_env.join(", ")
            ),
            "noo upgrade --stack   # recreates Grafana from the release's compose file",
        );
    }
    match &f.datasources {
        Some(files) => {
            let ds = datasource_findings(files, ini);
            if !ds.is_empty() {
                let lead = if f.viewer_grant == Some(true) {
                    format!(
                        "the gateway grants read-only users Grafana Viewer ({VIEWER_GRANT_ENV}=1) while Grafana's data \
                         sources do not go through it, so a read-only account could run any query"
                    )
                } else {
                    "a read-only account's own Grafana queries would not go through the gateway".to_string()
                };
                return fail(
                    format!("{lead}: {}", ds.join("; ")),
                    "noo upgrade --all   # from the current CLI release: lays the release's configs/grafana/ and compose down together and recreates Grafana",
                );
            }
        }
        None => {
            return Check {
                name: ROW,
                verdict: Verdict::Warn,
                detail: format!(
                    "SSO URL {root}; could not read configs/grafana/datasources/ to confirm Grafana's data sources dial the gateway"
                ),
                remedy: None,
            };
        }
    }
    if let Some(addrs) = &f.published {
        let wide: Vec<String> = addrs.iter().filter_map(|a| wide_bind(a)).collect();
        if !wide.is_empty() {
            return fail(
                format!("Grafana's port is published on {}", wide.join(", ")),
                "noo upgrade --stack   # moves NOO_GRAFANA_BIND_ADDR back to the door NOO_BIND_MODE names",
            );
        }
    }
    let mut fronted = String::new();
    if f.tailnet_unresolved {
        return Check {
            name: ROW,
            verdict: Verdict::Warn,
            detail: format!(
                "NOO_BIND_MODE asks for the tailnet door, but tailscale cannot name this box (not installed, or \
                 tailscaled down), so whether {root} reaches Grafana cannot be checked"
            ),
            remedy: Some("noo upgrade --stack   # once tailscaled is up: fronts Grafana's port with tailscale serve".to_string()),
        };
    }
    if let Some((port, serve)) = &f.fronting {
        use crate::tailnet_serve::GrafanaServe;
        let direct = f.published.as_deref().map(tailnet_publishes).unwrap_or_default();
        let loopback_only = f.published.as_ref().is_some_and(|a| !a.is_empty() && a.iter().all(|x| is_loopback(x)));
        let manual = crate::tailnet_serve::grafana_manual_line(*port);
        match serve {
            GrafanaServe::Fronted if direct.is_empty() => fronted = format!(", fronted by tailscale serve on :{port}"),
            GrafanaServe::Fronted => {
                return fail(
                    format!(
                        "tailscale serve fronts :{port}, but Grafana is still published on the tailnet ({}) rather than \
                         loopback, so serve's hop to 127.0.0.1 finds nothing",
                        direct.join(", ")
                    ),
                    "noo upgrade --stack   # the serve entry is confirmed, so the roll moves Grafana to loopback",
                );
            }
            GrafanaServe::Elsewhere(t) => {
                let path = if loopback_only { "NO browser path from other machines" } else { "browsers meet the cluster CA's untrusted certificate" };
                return fail(
                    format!("tailscale serve sends :{port} to {t}, not Grafana, and noo will not overwrite it: {path}"),
                    "noo upgrade --stack   # after freeing the port in `tailscale serve status`",
                );
            }
            GrafanaServe::Absent if loopback_only => {
                return fail(
                    format!("Grafana has NO browser path from other machines: it is published on loopback and tailscale serve does not answer :{port}, so {root} reaches nothing"),
                    "noo upgrade --stack   # fronts Grafana's port with tailscale serve",
                );
            }
            GrafanaServe::Absent => {
                let on = if direct.is_empty() { "its door".to_string() } else { format!("the tailnet ({})", direct.join(", ")) };
                return fail(
                    format!(
                        "Grafana is published straight on {on} with no tailscale serve entry for :{port}, so browsers \
                         meet the cluster CA's certificate instead of the tailnet's and refuse it"
                    ),
                    "noo upgrade --stack   # fronts the port with tailscale serve, then publishes Grafana on loopback",
                );
            }
            GrafanaServe::Unknown(e) => {
                let path = if loopback_only {
                    "if serve is not answering, Grafana has NO browser path from other machines"
                } else {
                    "browsers meet the cluster CA's untrusted certificate meanwhile"
                };
                return Check {
                    name: ROW,
                    verdict: Verdict::Warn,
                    detail: format!(
                        "SSO URL {root}; could not read tailscale serve to confirm it fronts :{port} ({e}); {path}. By hand: {manual}"
                    ),
                    remedy: Some("noo upgrade --stack   # once tailscaled is up".to_string()),
                };
            }
        }
    }
    if let Some((login, console)) = &f.bookmark {
        use crate::tailnet_serve::LoginRedirect;
        let port = f.fronting.as_ref().map(|(p, _)| *p).unwrap_or(BASE_PORT);
        let gap = match (login, console.as_deref().map(str::trim)) {
            (LoginRedirect::Mapped, Some(c)) if !c.is_empty() => None,
            (LoginRedirect::Mapped, None) => None, // could not read Grafana's env: no claim either way
            (LoginRedirect::Mapped, Some(_)) => Some(format!(
                "tailscale serve sends :{port}{} to Grafana's /logout, but the running Grafana has no {CONSOLE_URL_KEY}, so it goes to Grafana's bare welcome page",
                crate::tailnet_serve::GRAFANA_LOGIN_MOUNT
            )),
            (LoginRedirect::Elsewhere(t), _) => Some(format!(
                "tailscale serve sends :{port}{} to {t}, which noo leaves alone",
                crate::tailnet_serve::GRAFANA_LOGIN_MOUNT
            )),
            (LoginRedirect::Absent, _) => Some(format!(
                "tailscale serve has no :{port}{} entry",
                crate::tailnet_serve::GRAFANA_LOGIN_MOUNT
            )),
            (LoginRedirect::Unknown(e), _) => Some(format!("could not read tailscale serve ({e})")),
        };
        if let Some(gap) = gap {
            return Check {
                name: ROW,
                verdict: Verdict::Warn,
                detail: format!(
                    "SSO on at {root}, but a bookmark of it is a dead end: {gap}. Open Grafana from the console \
                     (Diagnostics → Observe → Open Grafana) works meanwhile"
                ),
                remedy: Some("noo upgrade --stack   # maps /login on Grafana's port to the console and recreates Grafana".to_string()),
            };
        }
    }
    if f.viewer_grant == Some(false) {
        return Check {
            name: ROW,
            verdict: Verdict::Warn,
            detail: format!(
                "SSO on at {root}, data sources through the gateway, but the running gateway's compose does not declare \
                 {VIEWER_GRANT_ENV}=1, so read-only users get no Grafana (an older CLI release rendered it)"
            ),
            remedy: Some("noo upgrade --all   # run it from the current CLI release".to_string()),
        };
    }
    let on = match &f.published {
        Some(a) if !a.is_empty() => format!(", published on {} only", a.join(", ")),
        Some(_) => ", no published port".to_string(),
        None => ", Grafana not running".to_string(),
    };
    // The loopback door is a browser path from the controller itself only;
    // say so, and how another machine gets there.
    let local = if f.fronting.is_none() && is_loopback(&url_host(root)) {
        let port = root.rsplit_once(':').map(|(_, p)| p).unwrap_or("3000");
        format!(
            "; a browser on this controller only — from another machine, tunnel first: ssh -L {port}:127.0.0.1:{port} <controller>"
        )
    } else {
        String::new()
    };
    Check {
        name: ROW,
        verdict: Verdict::Ok,
        detail: format!(
            "SSO on at {root}; noomesh accounts are the only login; Prometheus and Loki through the gateway{on}{fronted}{local}"
        ),
        remedy: None,
    }
}

fn docker_inspect(name: &str, template: &str) -> Option<String> {
    let out = std::process::Command::new("docker").args(["inspect", "-f", template, name]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Read the facts off this controller. Values of the containers' other
/// environment variables are read and dropped here, never printed.
pub fn gather(root: &Path) -> Facts {
    let env_path = root.join(".env");
    let env_lines = |c: &str| docker_inspect(c, "{{range .Config.Env}}{{println .}}{{end}}");
    let gateway_env = env_lines(&crate::envfile::container("gateway"));
    let gateway_url = gateway_env.as_ref().map(|text| {
        text.lines()
            .find_map(|l| l.strip_prefix("NOO_GRAFANA_URL="))
            .unwrap_or("")
            .to_string()
    });
    let viewer_grant = gateway_env.as_ref().map(|text| {
        text.lines()
            .filter_map(|l| l.strip_prefix(VIEWER_GRANT_ENV).and_then(|r| r.strip_prefix('=')))
            .any(|v| v.trim() == "1")
    });
    let grafana = crate::envfile::container("grafana");
    let auth_env = env_lines(&grafana)
        .map(|text| {
            text.lines()
                .filter_map(|l| l.split_once('=').map(|(k, _)| k))
                .filter(|k| k.starts_with("GF_AUTH_"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let published = docker_inspect(&grafana, "{{json .HostConfig.PortBindings}}").map(|j| {
        let v: serde_json::Value = serde_json::from_str(j.trim()).unwrap_or_default();
        v.as_object()
            .into_iter()
            .flat_map(|m| m.values())
            .filter_map(|b| b.as_array())
            .flatten()
            .map(|b| {
                let ip = b["HostIp"].as_str().unwrap_or("");
                // Docker writes "" for "every interface".
                if ip.is_empty() { "0.0.0.0".to_string() } else { ip.to_string() }
            })
            .collect()
    });
    let datasources = std::fs::read_dir(root.join("configs/grafana/datasources")).ok().map(|rd| {
        let mut files: Vec<(String, String)> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().to_string();
                Some((name, std::fs::read_to_string(&p).ok()?))
            })
            .collect();
        files.sort();
        files
    });
    let declared = declared_door(&env_path);
    let fronting = declared.serve_port.map(|port| (port, crate::tailnet_serve::grafana_serve_status(port)));
    let grafana_console = env_lines(&grafana).map(|text| {
        text.lines().find_map(|l| l.strip_prefix(CONSOLE_URL_KEY).and_then(|r| r.strip_prefix('='))).unwrap_or("").to_string()
    });
    let bookmark = declared.serve_port.map(|port| (crate::tailnet_serve::grafana_login_status(port), grafana_console));
    let tailnet_unresolved = declared.serve_port.is_none() && asks_for_tailnet(&effective(&env_path, "NOO_BIND_MODE"));
    Facts {
        fronting,
        tailnet_unresolved,
        bookmark,
        root_url: effective(&env_path, ROOT_URL_KEY),
        gateway_url,
        ini: std::fs::read_to_string(root.join("configs/grafana/grafana.ini")).ok(),
        auth_env,
        published,
        datasources,
        viewer_grant,
    }
}

/// `GRAFANA_ROOT_URL` is process-global; tests that set or read it hold this.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    const SHIPPED_INI: &str = include_str!("../../../configs/grafana/grafana.ini");
    const SHIPPED_PROM: &str = include_str!("../../../configs/grafana/datasources/prometheus.yml");
    const SHIPPED_LOKI: &str = include_str!("../../../configs/grafana/datasources/loki.yml");

    fn shipped_datasources() -> Vec<(String, String)> {
        vec![("loki.yml".into(), SHIPPED_LOKI.into()), ("prometheus.yml".into(), SHIPPED_PROM.into())]
    }

    #[test]
    fn the_door_follows_the_bind_mode() {
        let t = door_for("tailnet", "ctl.example.ts.net.", "100.64.0.15", 3000);
        // The tailnet door is DECLARED on the tailnet IP (fail-safe) and
        // moves to loopback only once serve is confirmed.
        assert_eq!(t, Door {
            root_url: "https://ctl.example.ts.net:3000".into(),
            bind_addr: "100.64.0.15".into(),
            serve_port: Some(3000),
        });
        assert_eq!(t.settled(true).bind_addr, "127.0.0.1");
        assert_eq!(t.settled(false), t, "unconfirmed serve: unchanged");
        assert_eq!(t.host(), "ctl.example.ts.net");
        let loopback = Door { root_url: "https://localhost:3000".into(), bind_addr: "127.0.0.1".into(), serve_port: None };
        assert_eq!(door_for("local", "ctl.example.ts.net", "100.64.0.15", 3000), loopback);
        // `all` is the cluster plane on every interface, never Grafana.
        assert_eq!(door_for("all", "ctl.example.ts.net", "100.64.0.15", 3000), loopback);
        // tailnet mode on a box whose tailnet is down: loopback, not a guess.
        assert_eq!(door_for("tailnet", "", "", 3000), loopback);
        // A literal tailnet address in NOO_BIND_MODE is the tailnet door, fronted the same way.
        let lit = door_for("100.64.0.9", "ctl.example.ts.net", "", 4000);
        assert_eq!((lit.bind_addr.as_str(), lit.serve_port), ("100.64.0.9", Some(4000)));
        assert_eq!(lit.settled(true).bind_addr, "127.0.0.1");
        // The loopback door never moves.
        assert_eq!(loopback.settled(true), loopback);
        // The instance offset reaches the served port.
        assert_eq!(door_for("tailnet", "ctl.example.ts.net", "100.64.0.9", 3100).serve_port, Some(3100));
        // A literal LAN address is not.
        assert_eq!(door_for("192.168.1.5", "ctl.example.ts.net", "", 3000), loopback);
        // The instance offset reaches the URL.
        assert_eq!(door_for("local", "", "", 4000).root_url, "https://localhost:4000");
    }

    /// The upgrade path: an install with SSO off (no GRAFANA_ROOT_URL) is
    /// repaired by the roll, both keys, and a set one is left alone.
    #[test]
    fn an_install_with_sso_off_is_repaired_and_a_set_one_is_kept() {
        let door = door_for("tailnet", "ctl.example.ts.net", "100.64.0.15", 3000).settled(true);
        let r = plan("", "127.0.0.1", &door);
        assert_eq!(r.iter().map(|r| (r.key, r.value.as_str())).collect::<Vec<_>>(), vec![
            (ROOT_URL_KEY, "https://ctl.example.ts.net:3000"),
        ]);
        // Serve NOT confirmed: SSO on, published on the tailnet IP as before.
        let unconfirmed = door_for("tailnet", "ctl.example.ts.net", "100.64.0.15", 3000);
        let r2 = plan("", "127.0.0.1", &unconfirmed);
        assert_eq!(r2.iter().map(|r| (r.key, r.value.as_str())).collect::<Vec<_>>(), vec![
            (ROOT_URL_KEY, "https://ctl.example.ts.net:3000"),
            (BIND_ADDR_KEY, "100.64.0.15"),
        ]);
        assert!(r[0].why.contains("single sign-on was off"), "{}", r[0].why);
        assert!(plan("https://grafana.example:3000", "127.0.0.1", &door).is_empty());
        // A wide publish is put back on the door even when the URL is set.
        let wide = plan("https://ctl.example.ts.net:3000", "0.0.0.0", &door);
        assert_eq!(wide.len(), 1);
        assert_eq!((wide[0].key, wide[0].value.as_str()), (BIND_ADDR_KEY, "127.0.0.1"));
    }

    /// host8 on 2026-10-02: URL set, port published on the tailnet IP. The
    /// roll moves it to loopback and keeps the URL.
    #[test]
    fn a_direct_tailnet_publish_moves_to_loopback_and_keeps_the_url() {
        let declared = door_for("tailnet", "ctl.example.ts.net", "100.64.0.12", 3000);
        // Before serve is confirmed: nothing moves.
        assert!(plan("https://ctl.example.ts.net:3000", "100.64.0.12", &declared).is_empty());
        let door = declared.settled(true);
        let r = plan("https://ctl.example.ts.net:3000", "100.64.0.12", &door);
        assert_eq!(r.iter().map(|r| (r.key, r.value.as_str())).collect::<Vec<_>>(), vec![(BIND_ADDR_KEY, "127.0.0.1")]);
        assert!(r[0].why.contains("tailscale serve"), "{}", r[0].why);
        assert!(plan("https://ctl.example.ts.net:3000", "127.0.0.1", &door).is_empty(), "idempotent");
        // An empty value is compose's 127.0.0.1 default: nothing to do.
        assert!(plan("https://ctl.example.ts.net:3000", "", &door).is_empty());
        // A non-tailnet mode keeps an operator's tailnet-IP publish, as before.
        let local = door_for("local", "ctl.example.ts.net", "100.64.0.12", 3000).settled(true);
        assert!(plan("https://localhost:3000", "100.64.0.12", &local).is_empty());
        // tailnet mode with tailscale unable to name the box: nothing moves either.
        let unresolved = door_for("tailnet", "", "", 3000).settled(true);
        assert!(plan("https://ctl.example.ts.net:3000", "100.64.0.12", &unresolved).is_empty());
    }

    fn temp_env(tag: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("noo-grafana-door-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join(".env");
        std::fs::write(&env, body).unwrap();
        env
    }

    /// FAIL-SAFE: the serve write fails (no tailscale, tailscaled down, no
    /// operator, or the port is someone else's) → the publish stays on the
    /// tailnet IP and the report carries a warning naming the manual step.
    #[test]
    fn a_failed_serve_write_keeps_the_tailnet_publish_and_warns() {
        use crate::tailnet_serve::{FrontError, Fronting};
        let _env = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        std::env::remove_var(CONSOLE_URL_KEY);
        let body = "NOO_BIND_MODE=tailnet\nGRAFANA_ROOT_URL=https://ctl.example.ts.net:3000\nNOO_GRAFANA_BIND_ADDR=100.64.0.12\n";
        let declared = door_for("tailnet", "ctl.example.ts.net", "100.64.0.12", 3000);

        let env = temp_env("failwrite", body);
        let rep = reconcile_door(&env, &declared, "", &|_| Err(FrontError::Write("`tailscale serve …` failed: tailscaled is not running".into())), &|_| panic!("no /login without a confirmed /"));
        assert_eq!(crate::onboard::env::read_env_key(&env, BIND_ADDR_KEY), "100.64.0.12", "must not strand Grafana on loopback");
        let w = rep.warning().expect("a warning");
        assert!(w.contains("stays published on the tailnet IP 100.64.0.12"), "{w}");
        assert!(w.contains("tailscale serve --bg --https=3000 https://127.0.0.1:3000") && w.contains("noo upgrade --stack"), "{w}");
        assert!(!w.contains("insecure"), "{w}");

        let env = temp_env("occupied", body);
        let rep = reconcile_door(&env, &declared, "", &|_| Err(FrontError::Occupied("http://127.0.0.1:9999".into())), &|_| panic!("no /login without a confirmed /"));
        assert_eq!(crate::onboard::env::read_env_key(&env, BIND_ADDR_KEY), "100.64.0.12");
        assert!(rep.warning().unwrap().contains("leaves alone"));

        // Confirmed: moved to loopback, URL kept, no warning.
        std::env::remove_var(CONSOLE_URL_KEY);
        let env = temp_env("ok", body);
        let rep = reconcile_door(&env, &declared, "", &|_| Ok(Fronting::Written), &|_| Ok(Fronting::Written));
        assert_eq!(crate::onboard::env::read_env_key(&env, BIND_ADDR_KEY), "127.0.0.1");
        assert_eq!(crate::onboard::env::read_env_key(&env, ROOT_URL_KEY), "https://ctl.example.ts.net:3000");
        assert!(rep.warning().is_none());
        assert_eq!(rep.login, Some(Ok(Fronting::Written)));
        assert!(rep.login_warning().is_none());
        // The bookmark redirect's target: the console's Open Grafana.
        assert_eq!(crate::onboard::env::read_env_key(&env, CONSOLE_URL_KEY), "https://ctl.example.ts.net/#/observability?open=grafana");
        std::env::remove_var(CONSOLE_URL_KEY);

        // `/` confirmed, `/login` refused: SSO and the door stand, the
        // warning names the manual line.
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        let env = temp_env("loginfail", body);
        let rep = reconcile_door(&env, &declared, "", &|_| Ok(Fronting::Already), &|_| Err("tailscale serve already sends :3000/login to x, which noo leaves alone".into()));
        assert_eq!(crate::onboard::env::read_env_key(&env, BIND_ADDR_KEY), "127.0.0.1");
        assert!(rep.warning().is_none());
        let w = rep.login_warning().expect("a bookmark warning");
        assert!(w.contains("tailscale serve --bg --https=3000 --set-path=/login https://127.0.0.1:3000/logout"), "{w}");
        assert!(w.contains("Open Grafana from the console still works"), "{w}");
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        std::env::remove_var(CONSOLE_URL_KEY);
        let _ = std::fs::remove_dir_all(env.parent().unwrap());
    }

    /// No tailscale binary at all: the declared door is loopback (no name),
    /// nothing is fronted or moved, and the roll goes on.
    #[test]
    fn no_tailscale_leaves_the_door_alone() {
        let _env = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(ROOT_URL_KEY);
        std::env::remove_var(BIND_ADDR_KEY);
        let env = temp_env("nots", "NOO_BIND_MODE=tailnet\nGRAFANA_ROOT_URL=https://ctl.example.ts.net:3000\nNOO_GRAFANA_BIND_ADDR=100.64.0.12\n");
        let declared = door_for("tailnet", "", "", 3000);
        let called = std::cell::Cell::new(false);
        let rep = reconcile_door(&env, &declared, "", &|_| {
            called.set(true);
            Ok(crate::tailnet_serve::Fronting::Written)
        }, &|_| {
            called.set(true);
            Ok(crate::tailnet_serve::Fronting::Written)
        });
        assert!(rep.login.is_none());
        assert!(!called.get(), "no tailnet name: serve is not touched");
        assert!(rep.front.is_none() && rep.warning().is_none());
        assert_eq!(rep.said, Ok(vec![]));
        assert_eq!(crate::onboard::env::read_env_key(&env, BIND_ADDR_KEY), "100.64.0.12");
        let _ = std::fs::remove_dir_all(env.parent().unwrap());
    }

    #[test]
    fn reconcile_writes_env_and_the_process_environment() {
        let _env = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("noo-grafana-door-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join(".env");
        std::fs::write(&env, "NOO_BIND_MODE=local\nGRAFANA_ROOT_URL=\nNOO_GRAFANA_BIND_ADDR=127.0.0.1\n").unwrap();
        std::env::remove_var(ROOT_URL_KEY);
        let door = door_for("local", "", "", 3000);
        let said = reconcile_env(&env, &door, "").unwrap();
        assert_eq!(said.len(), 1, "{said:?}");
        assert_eq!(crate::onboard::env::read_env_key(&env, ROOT_URL_KEY), "https://localhost:3000");
        assert_eq!(std::env::var(ROOT_URL_KEY).unwrap(), "https://localhost:3000");
        assert!(reconcile_env(&env, &door, "").unwrap().is_empty(), "idempotent");
        assert_eq!(crate::onboard::env::read_env_key(&env, CONSOLE_URL_KEY), "", "the loopback door has no serve to redirect");
        std::env::remove_var(ROOT_URL_KEY);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The upgrade path runs the repair, before the launcher starts the stack.
    #[test]
    fn the_stack_roll_repairs_the_door_before_launching() {
        let src = include_str!("upgrade.rs");
        let list = crate::commands::upgrade::phase_src::list();
        let call = list.find("\n    reconcile_grafana_door(g, &roll.root);").expect("upgrade_stack must call reconcile_grafana_door");
        let launch = list.find("launch_stack(").expect("the launcher phase");
        assert!(call < launch, "the door must be written before the launcher recreates the stack");
        let f = src.split("fn reconcile_grafana_door(").nth(1).expect("reconcile_grafana_door exists");
        let f = f.split("\n}\n").next().unwrap();
        assert!(f.contains("gd::ensure_leaf_names_door("));
        // The tailnet door is fronted by the same roll, and settled on the outcome.
        assert!(f.contains("gd::reconcile_door(") && f.contains("ensure_grafana_fronted("),
            "the roll must front Grafana's port with tailscale serve before settling the door");
    }

    #[test]
    fn wide_binds_are_named() {
        for ok in ["", "127.0.0.1", "::1", "localhost", "100.64.0.15"] {
            assert_eq!(wide_bind(ok), None, "{ok}");
        }
        for bad in ["0.0.0.0", "::", "192.168.1.5"] {
            assert!(wide_bind(bad).is_some(), "{bad}");
        }
    }

    /// The release's grafana.ini has no login but a noomesh token.
    #[test]
    fn the_shipped_grafana_ini_has_no_local_login() {
        assert_eq!(login_findings(SHIPPED_INI), Vec::<String>::new());
    }

    fn facts(ini: &str) -> Facts {
        Facts {
            root_url: "https://localhost:3000".into(),
            gateway_url: Some("https://localhost:3000".into()),
            ini: Some(ini.to_string()),
            auth_env: vec![],
            published: Some(vec!["127.0.0.1".into()]),
            datasources: Some(shipped_datasources()),
            viewer_grant: Some(true),
            fronting: None,
            tailnet_unresolved: false,
            bookmark: None,
        }
    }

    fn tailnet_facts() -> Facts {
        let url = "https://ctl.example.ts.net:3000".to_string();
        Facts {
            root_url: url.clone(),
            gateway_url: Some(url),
            published: Some(vec!["127.0.0.1".into()]),
            fronting: Some((3000, crate::tailnet_serve::GrafanaServe::Fronted)),
            bookmark: Some((
                crate::tailnet_serve::LoginRedirect::Mapped,
                Some("https://ctl.example.ts.net/#/observability?open=grafana".into()),
            )),
            ..facts(SHIPPED_INI)
        }
    }

    /// The tailnet door: OK only when Grafana is loopback-bound AND serve
    /// fronts its port; a direct tailnet publish is the untrusted-cert case
    /// again and FAILs naming the roll.
    #[test]
    fn the_tailnet_door_needs_loopback_and_the_serve_entry() {
        use crate::tailnet_serve::GrafanaServe;
        let c = door_check(&tailnet_facts());
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("fronted by tailscale serve on :3000"), "{}", c.detail);
        assert!(!c.detail.contains("ssh -L"), "the tailnet door needs no tunnel");

        // host8 today: published straight on the tailnet IP, no serve entry.
        let mut f = tailnet_facts();
        f.published = Some(vec!["100.64.0.12".into()]);
        f.fronting = Some((3000, GrafanaServe::Absent));
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("straight on the tailnet (100.64.0.12)") && c.detail.contains("cluster CA"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"));

        // Serve confirmed but the publish never moved: FAIL, the roll moves it.
        let mut f = tailnet_facts();
        f.published = Some(vec!["100.64.0.12".into()]);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"));

        // Loopback with nothing in front: NO browser path, said loudly.
        let mut f = tailnet_facts();
        f.fronting = Some((3000, GrafanaServe::Absent));
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("NO browser path"), "{}", c.detail);
        assert!(c.remedy.as_deref().unwrap().starts_with("noo upgrade --stack"));

        // The operator's own entry on the port: FAIL, never overwritten.
        f.fronting = Some((3000, GrafanaServe::Elsewhere("http://127.0.0.1:9999".into())));
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("will not overwrite") && c.detail.contains("NO browser path"), "{}", c.detail);

        // tailscaled down: WARN, never OK, naming the manual step.
        f.fronting = Some((3000, GrafanaServe::Unknown("no tailscale".into())));
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Warn, "unreadable is never an OK");
        assert!(c.detail.contains("tailscale serve --bg --https=3000 https://127.0.0.1:3000"), "{}", c.detail);

        // No tailscale binary / no tailnet name in tailnet mode: WARN.
        let mut f = facts(SHIPPED_INI);
        f.tailnet_unresolved = true;
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains("tailscale cannot name this box"), "{}", c.detail);
        // No operator-facing text suggests dropping TLS verification.
        for g in [GrafanaServe::Absent, GrafanaServe::Elsewhere("x".into())] {
            let mut f = tailnet_facts();
            f.fronting = Some((3000, g));
            let c = door_check(&f);
            let text = format!("{} {}", c.detail, c.remedy.unwrap_or_default());
            assert!(!text.contains("insecure"), "{text}");
        }
    }

    /// The Viewer grant on with direct data sources is the
    /// hole itself — FAIL, saying so; the grant off with gateway data
    /// sources only withholds Grafana from read-only users — WARN.
    #[test]
    fn the_row_fails_the_viewer_grant_over_direct_data_sources() {
        let direct = SHIPPED_PROM.replace("https://gateway:8080/api/grafana-ds/prometheus", "https://prometheus:9090");
        assert_ne!(direct, SHIPPED_PROM, "the replace must hit");
        let mut f = facts(SHIPPED_INI);
        f.datasources = Some(vec![("loki.yml".into(), SHIPPED_LOKI.into()), ("prometheus.yml".into(), direct)]);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("grants read-only users Grafana Viewer") && c.detail.contains("prometheus:9090"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo upgrade --all"));
        // The grant off, data sources direct: still a FAIL (drift), without the grant claim.
        f.viewer_grant = Some(false);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(!c.detail.contains("grants read-only users"), "{}", c.detail);
        // The grant off, data sources right: a WARN naming the fix.
        let mut f = facts(SHIPPED_INI);
        f.viewer_grant = Some(false);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
        assert!(c.detail.contains(VIEWER_GRANT_ENV), "{}", c.detail);
        // Both right: OK.
        assert_eq!(door_check(&facts(SHIPPED_INI)).verdict, Verdict::Ok);
    }

    /// The compose this CLI ships declares the grant; the gateway reads the
    /// same name.
    #[test]
    fn the_shipped_compose_declares_the_viewer_grant() {
        let compose = include_str!("../../../docker-compose.cluster.yml");
        assert!(compose.contains(&format!("      - {VIEWER_GRANT_ENV}=1\n")), "the gateway service must carry {VIEWER_GRANT_ENV}=1");
        let auth = include_str!("../../../gateway-rust/src/auth.rs");
        assert!(auth.contains(&format!("pub const GRAFANA_DS_GATE_ENV: &str = \"{VIEWER_GRANT_ENV}\";")));
    }

    /// The release's data sources dial the gateway and
    /// grafana.ini tells it who is looking.
    #[test]
    fn the_shipped_data_sources_dial_the_gateway() {
        assert_eq!(datasource_findings(&shipped_datasources(), SHIPPED_INI), Vec::<String>::new());
    }

    /// A data source put back on Prometheus or Loki directly hands every
    /// read-only account its own queries: FAIL, naming the file and the fix.
    #[test]
    fn the_row_fails_a_data_source_that_skips_the_gateway() {
        let mut f = facts(SHIPPED_INI);
        let direct = SHIPPED_LOKI.replace("https://gateway:8080/api/grafana-ds/loki", "https://loki:3100");
        assert_ne!(direct, SHIPPED_LOKI, "the replace must hit");
        f.datasources = Some(vec![("loki.yml".into(), direct), ("prometheus.yml".into(), SHIPPED_PROM.into())]);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("loki.yml") && c.detail.contains("https://loki:3100"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo upgrade --all"));
        // A missing data source is not a pass.
        let mut f = facts(SHIPPED_INI);
        f.datasources = Some(vec![("prometheus.yml".into(), SHIPPED_PROM.into())]);
        assert_eq!(door_check(&f).verdict, Verdict::Fail);
        // Unreadable: a warning, never an OK.
        let mut f = facts(SHIPPED_INI);
        f.datasources = None;
        assert_eq!(door_check(&f).verdict, Verdict::Warn);
        // The two grafana.ini switches.
        let no_user = SHIPPED_INI.replace("send_user_header = true", "send_user_header = false");
        assert_ne!(no_user, SHIPPED_INI);
        assert_eq!(door_check(&facts(&no_user)).verdict, Verdict::Fail);
        let at = SHIPPED_INI.find("[public_dashboards]").expect("the section");
        let off = at + SHIPPED_INI[at..].find("enabled = false").expect("its switch");
        let public = format!("{}enabled = true{}", &SHIPPED_INI[..off], &SHIPPED_INI[off + "enabled = false".len()..]);
        assert_eq!(door_check(&facts(&public)).verdict, Verdict::Fail);
    }

    #[test]
    fn the_row_passes_a_closed_door() {
        let c = door_check(&facts(SHIPPED_INI));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    #[test]
    fn the_row_fails_sso_off_naming_the_fix() {
        let mut f = facts(SHIPPED_INI);
        f.root_url.clear();
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("single sign-on is off"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo upgrade --stack"));
        // Set in .env but the running gateway predates it.
        let mut f = facts(SHIPPED_INI);
        f.gateway_url = Some(String::new());
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert_eq!(c.remedy.as_deref(), Some("noo stack restart --force"));
        let mut f = facts(SHIPPED_INI);
        f.root_url = "http://localhost:3000".into();
        assert_eq!(door_check(&f).verdict, Verdict::Fail);
    }

    /// The pre-1259 grafana.ini: login form hidden, basic auth ON — the
    /// local admin password logged in over HTTP (measured 2026-09-30 on
    /// the 12.4 image: `curl -u admin:<pw> /api/user` answered 200).
    #[test]
    fn the_row_fails_a_local_login() {
        let open = "[auth]\ndisable_login_form = true\n[auth.basic]\nenabled = true\n[auth.jwt]\nenabled = true\n";
        let c = door_check(&facts(open));
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("disable_login") && c.detail.contains("[auth.basic]"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo upgrade --stack"));
        // Absent keys are Grafana's defaults: login on, basic on.
        let bare = "[auth.jwt]\nenabled = true\n";
        assert_eq!(login_findings(bare).len(), 2);
        let anon = SHIPPED_INI.replace("[auth.anonymous]\nenabled = false", "[auth.anonymous]\nenabled = true");
        assert_eq!(door_check(&facts(&anon)).verdict, Verdict::Fail);
        // An environment override outranks the file.
        let mut f = facts(SHIPPED_INI);
        f.auth_env = vec!["GF_AUTH_BASIC_ENABLED".into()];
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("GF_AUTH_BASIC_ENABLED"), "{}", c.detail);
    }

    #[test]
    fn the_row_fails_a_wide_publish() {
        let mut f = facts(SHIPPED_INI);
        f.published = Some(vec!["0.0.0.0".into()]);
        let c = door_check(&f);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("every interface"), "{}", c.detail);
        // A non-tailnet door keeps an operator's tailnet-IP publish (as before).
        f.published = Some(vec!["100.64.0.15".into()]);
        assert_eq!(door_check(&f).verdict, Verdict::Ok);
    }

    /// The loopback door is a browser path from the controller itself only:
    /// the OK row says so, and how to tunnel from elsewhere.
    #[test]
    fn the_loopback_door_says_it_is_local_only() {
        let c = door_check(&facts(SHIPPED_INI));
        assert_eq!(c.verdict, Verdict::Ok);
        assert!(c.detail.contains("ssh -L 3000:127.0.0.1:3000"), "{}", c.detail);
    }

    /// No phone-home: the release's grafana.ini turns every outbound call
    /// off, and the row FAILs a live ini that turned one back on.
    #[test]
    fn the_shipped_grafana_ini_calls_nobody() {
        assert_eq!(phone_home_findings(SHIPPED_INI), Vec::<String>::new());
        // Every switch is spelled out in the file, not left to a default.
        for (sec, key, off, _, _) in PHONE_HOME {
            assert_eq!(ini_value(SHIPPED_INI, sec, key).as_deref(), Some(*off), "[{sec}] {key}");
        }
        // An absent key is Grafana's default: on.
        assert_eq!(phone_home_findings("").len(), PHONE_HOME.len() + 1);
    }

    #[test]
    fn the_row_fails_a_grafana_that_calls_home() {
        let on = SHIPPED_INI.replace("check_for_updates = false", "check_for_updates = true");
        assert_ne!(on, SHIPPED_INI, "the replace must hit");
        let c = door_check(&facts(&on));
        assert_eq!(c.verdict, Verdict::Fail, "{}", c.detail);
        assert!(c.detail.contains("calls home") && c.detail.contains("check_for_updates"), "{}", c.detail);
        assert!(c.remedy.unwrap().starts_with("noo upgrade --stack"));
        // The ini before this release: no [analytics] at all.
        let at = SHIPPED_INI.find("[analytics]").expect("the section");
        let stale = &SHIPPED_INI[..at];
        assert_eq!(door_check(&facts(stale)).verdict, Verdict::Fail);
        // The catalog backstop back on grafana.com.
        let api = SHIPPED_INI.replace("api_url = http://127.0.0.1:9/api", "api_url = https://grafana.com/api");
        assert_ne!(api, SHIPPED_INI);
        assert!(door_check(&facts(&api)).detail.contains("[grafana_com] api_url"));
    }

    /// The bookmark redirect: the tailnet door's row WARNs (never OK, never
    /// FAIL — Open Grafana still works) when `/login` is not mapped or the
    /// running Grafana has nowhere to send it.
    #[test]
    fn the_row_warns_a_bookmark_that_dead_ends() {
        use crate::tailnet_serve::LoginRedirect;
        assert_eq!(door_check(&tailnet_facts()).verdict, Verdict::Ok);
        for (login, console, want) in [
            (LoginRedirect::Absent, Some("https://x/#/observability?open=grafana".to_string()), "no :3000/login entry"),
            (LoginRedirect::Elsewhere("http://127.0.0.1:1".into()), None, "leaves alone"),
            (LoginRedirect::Mapped, Some(String::new()), CONSOLE_URL_KEY),
            (LoginRedirect::Unknown("no tailscale".into()), None, "could not read tailscale serve"),
        ] {
            let mut f = tailnet_facts();
            f.bookmark = Some((login, console));
            let c = door_check(&f);
            assert_eq!(c.verdict, Verdict::Warn, "{}", c.detail);
            assert!(c.detail.contains(want) && c.detail.contains("Diagnostics → Observe → Open Grafana"), "{}", c.detail);
            assert!(c.remedy.unwrap().starts_with("noo upgrade --stack"));
        }
    }

    /// Only the tailnet door gets a console URL; a set one is kept; the
    /// instance prefix reaches it.
    #[test]
    fn the_console_url_follows_the_door_and_the_instance() {
        let t = door_for("tailnet", "ctl.example.ts.net", "100.64.0.12", 3000);
        assert_eq!(console_plan("", &t, "").unwrap().value, "https://ctl.example.ts.net/#/observability?open=grafana");
        assert_eq!(console_plan("", &t, "obtest").unwrap().value, "https://ctl.example.ts.net/obtest/#/observability?open=grafana");
        assert!(console_plan("https://elsewhere/", &t, "").is_none(), "kept");
        assert!(console_plan("", &door_for("local", "", "", 3000), "").is_none());
        assert_eq!(canonical_instance("mesh"), "");
        assert_eq!(canonical_instance(" noomesh "), "");
        assert_eq!(canonical_instance("obtest"), "obtest");
    }

    /// grafana.ini sends `/logout` to the console URL compose passes, and
    /// compose passes it.
    #[test]
    fn grafana_sends_logout_to_the_console() {
        assert_eq!(
            ini_value(SHIPPED_INI, "auth", "signout_redirect_url").as_deref(),
            Some(format!("$__env{{{}}}", CONSOLE_URL_KEY.to_ascii_lowercase()).as_str())
        );
        let compose = include_str!("../../../docker-compose.cluster.yml");
        assert!(compose.contains(&format!("      - {CONSOLE_URL_KEY}=${{{CONSOLE_URL_KEY}:-}}\n")));
    }
}
