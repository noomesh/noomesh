// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The harness's own check that it is held off the internet (enforcement
//! step 1, docs/security/telemetry.md).
//!
//! The applier renders a drop-in for noo-harness.service: `IPAddressDeny=any`
//! with a local/tailnet allowlist, and a unit-private resolver (a
//! resolv.conf whose only nameserver is outside the allowlist, a rendered
//! hosts file, the system resolver's sockets made inaccessible). Every vendor
//! CLI the harness launches inherits both: its cgroup and its mount
//! namespace. Rendered files prove nothing about the running process, so at
//! start the harness tries, from inside its own namespace:
//!
//! - to resolve [`CANARY_NAME`]: under the unit resolver the question cannot
//!   leave the machine and the lookup fails;
//! - to connect to [`CANARY_ADDR`], 127.0.0.2:9: loopback (no packet ever
//!   leaves the host), outside the allowlist (only 127.0.0.1 of 127/8 is
//!   allowed), nothing listening. Unrestricted, the kernel answers RST at
//!   once ("refused"). Under the allowlist the SYN is dropped, which TCP
//!   surfaces as EPERM or, on real systemd 249/255, as a timeout. A TEST-NET
//!   target could not tell the two apart: it times out either way.
//!
//! It writes the result to [`SELFTEST_FILE`] (world-readable; it holds no
//! secret) with its pid, so the node agent can tell the result belongs to
//! the unit's running process (`MainPID`) and report it in the heartbeat.
//! The directory exists only under the drop-in (`RuntimeDirectory=`); without
//! it nothing is written and the agent reports "unknown", never "enforced".
//!
//! When the unit is NOT restricted, the lookup canary can leave the machine (a
//! DNS question for example.com, the IANA reserved example domain); the
//! connect canary never does.
//!
//! It runs again every [`RECHECK_EVERY`], not only at start: a host can change
//! what a running unit sees (a resolver rewriting its file), so a check made at
//! start says nothing about an hour later (i1246). Each run also asks every
//! address the unit may reach ([`ALLOW_FILE`], rendered by the applier) for
//! DNS: an answer means a name can leave through it, so not held. It checks the
//! unit's private resolv.conf still holds (a lost one is a warning: the allow
//! list still holds), and that the gateway answers (a stale allow list cuts it
//! off). Under an installed hold ([`HOLD_ENV`]) a check that is not held stops
//! the harness taking work until a later check holds again; with no hold
//! installed (a node where the applier left it off) it keeps serving, as before.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

/// The runtime directory the drop-in creates (`RuntimeDirectory=noo-harness`).
pub const SELFTEST_DIR: &str = "/run/noo-harness";
/// The self-test result the node agent reads.
pub const SELFTEST_FILE: &str = "/run/noo-harness/egress.json";
/// A name that must not resolve from inside the unit.
pub const CANARY_NAME: &str = "example.com";
/// An address the unit must not be able to connect to: loopback, outside
/// the allowlist, nothing listening.
pub const CANARY_ADDR: &str = "127.0.0.2:9";
/// Each canary's bound: a refused one answers at once; only a broken
/// enforcement waits this long.
const CANARY_TIMEOUT: Duration = Duration::from_secs(3);
/// How often the check runs again after start. The node agent reads a record
/// older than three of these as unknown.
pub const RECHECK_EVERY: Duration = Duration::from_secs(60);
/// The addresses the unit may reach, one per line (the applier renders it
/// beside the drop-in): each is asked for DNS every run.
pub const ALLOW_FILE: &str = "/etc/noo/harness-net/allow";
/// The only nameserver the unit's private resolv.conf names (TEST-NET-1).
pub const HELD_NAMESERVER: &str = "192.0.2.53";
/// Set to `1` by the drop-in: the hold is installed, so a check that is not
/// held must stop the harness taking work (fail closed).
pub const HOLD_ENV: &str = "NOO_HARNESS_EGRESS_HOLD";
/// How long one DNS question waits for an answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(1);

/// Whether the harness may take work: false only while an installed hold's
/// latest check is not held. Every loop that takes work asks this first.
static SERVING: AtomicBool = AtomicBool::new(true);
/// The last logged state, so a change is logged once: 0 none, 1 held, 2 not.
static LAST: AtomicU8 = AtomicU8::new(0);
/// The last logged resolv.conf state: 0 none, 1 held, 2 replaced.
static LAST_RESOLV: AtomicU8 = AtomicU8::new(0);

/// May the harness take work now?
pub fn serving() -> bool {
    SERVING.load(Ordering::SeqCst)
}

/// Serving follows the check only under an installed hold.
pub fn serving_for(hold_installed: bool, enforced: bool) -> bool {
    !hold_installed || enforced
}

/// Whether the unit's resolv.conf is still the private one: its first
/// nameserver is the held TEST-NET address. A host rewrite that detached the
/// bind shows the host's file here instead.
pub fn resolv_held(content: &str) -> bool {
    content
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("nameserver").map(str::trim))
        .is_some_and(|ns| ns == HELD_NAMESERVER)
}

/// The addresses in the allow file (one per line, `#` comments and junk skipped).
pub fn allowed_addrs(content: &str) -> Vec<IpAddr> {
    content.lines().filter_map(|l| l.trim().parse::<IpAddr>().ok()).collect()
}

/// A DNS question for the canary name (id 0x6e6f, recursion desired, type A).
pub fn dns_question() -> Vec<u8> {
    let mut q = vec![0x6e, 0x6f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for part in CANARY_NAME.split('.') {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    q
}

/// Whether `reply` is a DNS answer to [`dns_question`]: same id, the response
/// bit set, at least a header.
pub fn is_dns_answer(reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[0] == 0x6e && reply[1] == 0x6f && reply[2] & 0x80 != 0
}

/// Does anything answer DNS on `addr` port 53 from inside the unit? Denied,
/// refused or silent is no.
async fn dns_answers(addr: IpAddr) -> bool {
    let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("a literal address");
    let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else { return false };
    if sock.connect(SocketAddr::new(addr, 53)).await.is_err() || sock.send(&dns_question()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    matches!(tokio::time::timeout(DNS_TIMEOUT, sock.recv(&mut buf)).await, Ok(Ok(n)) if is_dns_answer(&buf[..n]))
}

/// The gateway's host and port from NOO_GATEWAY_URL (https 443, http 80).
pub fn gateway_target(url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(url).ok()?;
    let host = u.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    Some((host, u.port_or_known_default()?))
}

/// Can the gateway be reached from inside the unit? Through the unit's hosts
/// file, as the harness itself would.
async fn gateway_reachable(host: &str, port: u16) -> bool {
    matches!(tokio::time::timeout(CANARY_TIMEOUT, tokio::net::TcpStream::connect((host, port))).await, Ok(Ok(_)))
}

/// One check's full record: [`record`] plus what the periodic check adds.
/// `enforced` also needs the allow file to list something (with none, the
/// DNS check would pass having asked nobody) and no allowed address to answer
/// DNS; a replaced resolv.conf alone does not clear it (the allow list still
/// holds) and is carried as `resolv_held`. The DNS check asks over UDP.
pub fn record_full(base: Value, checked_at: u64, allow_listed: bool, resolv_held: bool, dns_reachable: &[String], gateway: Option<(String, bool)>) -> Value {
    let mut r = base;
    let enforced = r["enforced"] == Value::Bool(true) && allow_listed;
    r["allow_file"] = json!(if allow_listed { "ok" } else { "missing" });
    r["enforced"] = json!(enforced);
    r["checked_at"] = json!(checked_at);
    r["resolv_held"] = json!(resolv_held);
    r["dns_reachable"] = json!(dns_reachable);
    if let Some((addr, ok)) = gateway {
        r["gateway"] = json!({"addr": addr, "result": if ok { "ok" } else { "failed" }});
    }
    r
}

/// What a connect to the canary address came to.
pub fn connect_result(r: &io::Result<()>) -> String {
    match r {
        Ok(()) => "connected".into(),
        Err(e) if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) => "denied".into(),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => "refused".into(),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => "timeout".into(),
        Err(e) => format!("other:{e}"),
    }
}

/// A DNS server this unit could still reach: one listening on UDP port 53 at
/// 127.0.0.1, ::1 or a wildcard address (the unit's allowlist keeps exactly
/// 127.0.0.1 and ::1 of loopback, so a forwarder on 127.0.0.53, such as
/// systemd-resolved's stub, is already out of reach). A raw-DNS client inside
/// the unit could send a name there and the forwarder would carry it out, so
/// such a listener means "not held". Read from `/proc/net/udp{,6}` text:
/// nothing is sent. Returns the first such listener, as "<addr>:53".
pub fn reachable_dns_listener(udp: &str, udp6: &str) -> Option<String> {
    for line in udp.lines().skip(1) {
        let Some(local) = line.split_whitespace().nth(1) else { continue };
        match local {
            "0100007F:0035" => return Some("127.0.0.1:53".into()),
            "00000000:0035" => return Some("0.0.0.0:53".into()),
            _ => {}
        }
    }
    for line in udp6.lines().skip(1) {
        let Some(local) = line.split_whitespace().nth(1) else { continue };
        match local {
            "00000000000000000000000001000000:0035" => return Some("[::1]:53".into()),
            "00000000000000000000000000000000:0035" => return Some("[::]:53".into()),
            _ => {}
        }
    }
    None
}

/// The self-test record. `enforced` only when the lookup failed, the connect
/// canary was dropped (EPERM or a timeout, never "refused"), AND no DNS
/// server is reachable on the loopback the unit keeps.
pub fn record(pid: u32, started_at: u64, lookup_resolved: bool, connect: &str, loopback_dns: Option<&str>) -> Value {
    // A dropped SYN is EPERM ("denied") or a timeout; "refused" is the
    // unrestricted kernel answering for a port nobody listens on.
    let held = matches!(connect, "denied" | "timeout");
    let enforced = !lookup_resolved && held && loopback_dns.is_none();
    json!({
        "version": 1,
        "pid": pid,
        "started_at": started_at,
        "lookup": {"name": CANARY_NAME, "result": if lookup_resolved { "resolved" } else { "failed" }},
        "connect": {"addr": CANARY_ADDR, "result": connect},
        "loopback_dns": loopback_dns.unwrap_or("none"),
        "enforced": enforced,
    })
}

async fn lookup_resolves() -> bool {
    match tokio::time::timeout(CANARY_TIMEOUT, tokio::net::lookup_host((CANARY_NAME, 443))).await {
        Ok(Ok(mut addrs)) => addrs.next().is_some(),
        _ => false,
    }
}

async fn connect_canary() -> io::Result<()> {
    let addr: SocketAddr = CANARY_ADDR.parse().expect("a literal address");
    match tokio::time::timeout(CANARY_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "no answer within the bound")),
    }
}

/// Write `value` to `dir/egress.json` atomically (a temp file, then rename),
/// mode 0644.
pub fn write_into(dir: &Path, value: &Value) -> io::Result<()> {
    let tmp = dir.join(".egress.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(value)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, dir.join("egress.json"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// One check from inside the unit: every canary, the record written, and
/// whether the harness may take work set from it. None: no runtime directory
/// (no drop-in), nothing run.
pub async fn check_once(started_at: u64, gateway_url: &str) -> Option<Value> {
    let dir = Path::new(SELFTEST_DIR);
    if !dir.is_dir() {
        if LAST.swap(2, Ordering::SeqCst) != 2 {
            tracing::warn!("harness: no {SELFTEST_DIR}: this unit carries no egress drop-in, so nothing holds it off the internet (the agent reports egress unknown)");
        }
        return None;
    }
    let resolved = lookup_resolves().await;
    let connect = connect_result(&connect_canary().await);
    let udp = std::fs::read_to_string("/proc/net/udp").unwrap_or_default();
    let udp6 = std::fs::read_to_string("/proc/net/udp6").unwrap_or_default();
    let loopback_dns = reachable_dns_listener(&udp, &udp6);
    let held_resolv = resolv_held(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default());
    // A missing or empty allow file (an applier older than it) is not held:
    // the DNS check below would otherwise pass having asked nobody.
    let allowed = std::fs::read_to_string(ALLOW_FILE).map(|t| allowed_addrs(&t)).unwrap_or_default();
    let mut dns_reachable = Vec::new();
    for a in &allowed {
        if dns_answers(*a).await {
            dns_reachable.push(a.to_string());
        }
    }
    let gateway = match gateway_target(gateway_url) {
        Some((h, p)) => Some((format!("{h}:{p}"), gateway_reachable(&h, p).await)),
        None => None,
    };
    let base = record(std::process::id(), started_at, resolved, &connect, loopback_dns.as_deref());
    let rec = record_full(base, now_secs(), !allowed.is_empty(), held_resolv, &dns_reachable, gateway);
    let enforced = rec["enforced"] == Value::Bool(true);
    let hold_installed = std::env::var(HOLD_ENV).is_ok_and(|v| v.trim() == "1");
    SERVING.store(serving_for(hold_installed, enforced), Ordering::SeqCst);
    // Logged on a change only: no line a minute while nothing moves.
    let now = if enforced { 1 } else { 2 };
    if LAST.swap(now, Ordering::SeqCst) != now {
        if enforced {
            tracing::info!(lookup = "failed", connect = %connect, "harness: egress held: no internet name resolves, no internet address is reachable and no allowed address answers DNS");
        } else {
            tracing::error!(lookup = if resolved { "resolved" } else { "failed" }, connect = %connect, loopback_dns = loopback_dns.as_deref().unwrap_or("none"),
                dns_reachable = ?dns_reachable, taking_work = serving_for(hold_installed, enforced),
                "harness: egress NOT held: this unit can reach the internet or a DNS server");
        }
    }
    let r = if held_resolv { 1 } else { 2 };
    if LAST_RESOLV.swap(r, Ordering::SeqCst) != r && !held_resolv {
        tracing::warn!("harness: this unit's private resolv.conf was replaced by the host's (a host resolver rewrote its file); lookups are still denied by the allow list; a restart of the harness restores it");
    }
    if let Err(e) = write_into(dir, &rec) {
        tracing::error!(error = %e, file = SELFTEST_FILE, "harness: could not write the egress self-test (the agent reports egress unknown)");
    }
    Some(rec)
}

/// The check at start, before anything else connects, and then every
/// [`RECHECK_EVERY`] for the life of the process.
pub async fn run_at_start(gateway_url: &str) -> Option<Value> {
    let started_at = now_secs();
    let rec = check_once(started_at, gateway_url).await;
    let url = gateway_url.to_string();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RECHECK_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            check_once(started_at, &url).await;
        }
    });
    rec
}

#[cfg(test)]
mod tests {
    use super::*;

    /// i1246: a check that is not held stops the harness taking work only
    /// where the hold is installed; elsewhere it serves as before.
    #[test]
    fn only_an_installed_hold_that_is_not_held_stops_work() {
        assert!(!serving_for(true, false));
        assert!(serving_for(true, true));
        assert!(serving_for(false, false), "no hold installed: serve, as before");
        assert!(serving_for(false, true));
    }

    #[test]
    fn the_private_resolv_conf_is_recognised_and_a_host_one_is_not() {
        assert!(resolv_held("# Rendered by noo-apply\nnameserver 192.0.2.53\noptions timeout:1 attempts:1\n"));
        assert!(!resolv_held("nameserver 127.0.0.53\noptions edns0\n"));
        assert!(!resolv_held("nameserver 100.100.100.100\nnameserver 192.0.2.53\n"), "the FIRST nameserver decides");
        assert!(!resolv_held(""), "no file is not held");
    }

    #[test]
    fn the_allow_file_is_read_as_addresses() {
        let a = allowed_addrs("127.0.0.1\n::1\n# a comment\n10.0.0.5\nnot-an-address\n\nfd7a:115c:a1e0::7\n");
        assert_eq!(a.iter().map(|x| x.to_string()).collect::<Vec<_>>(), ["127.0.0.1", "::1", "10.0.0.5", "fd7a:115c:a1e0::7"]);
    }

    #[test]
    fn a_dns_answer_is_told_from_anything_else() {
        let q = dns_question();
        assert_eq!(&q[..2], &[0x6e, 0x6f]);
        assert!(q.windows(8).any(|w| w == b"\x07example"), "asks for the canary name");
        let mut answer = q.clone();
        answer[2] |= 0x80;
        assert!(is_dns_answer(&answer));
        assert!(!is_dns_answer(&q), "an echo of the question is not an answer");
        let mut other = answer.clone();
        other[1] = 0x00;
        assert!(!is_dns_answer(&other), "another id is not ours");
        assert!(!is_dns_answer(&answer[..11]), "shorter than a header");
    }

    #[test]
    fn an_answering_address_clears_enforced_and_a_replaced_resolv_conf_does_not() {
        let held = record(7, 1, false, "denied", None);
        let r = record_full(held.clone(), 100, true, true, &["10.0.0.5".into()], None);
        assert_eq!(r["enforced"], false, "a resolver answered at an allowed address");
        assert_eq!(r["dns_reachable"], json!(["10.0.0.5"]));
        let lost = record_full(held.clone(), 100, true, false, &[], Some(("ctl:8443".into(), true)));
        assert_eq!(lost["enforced"], true, "the allow list still holds");
        assert_eq!(lost["resolv_held"], false);
        assert_eq!(lost["gateway"], json!({"addr": "ctl:8443", "result": "ok"}));
        assert_eq!(lost["checked_at"], 100);
        let gw = record_full(held.clone(), 100, true, true, &[], Some(("ctl:8443".into(), false)));
        assert_eq!((gw["enforced"].clone(), gw["gateway"]["result"].clone()), (json!(true), json!("failed")), "a stale allow list is not a leak");
        let open = record_full(record(7, 1, true, "denied", None), 100, true, true, &[], None);
        assert_eq!(open["enforced"], false, "a resolving lookup stays not held");
        assert_eq!(open["version"], 1, "the record stays version 1 for the agents already out");
        let none = record_full(held, 100, false, true, &[], None);
        assert_eq!((none["enforced"].clone(), none["allow_file"].clone()), (json!(false), json!("missing")),
            "no allow file: the DNS check asked nobody, so never held");
    }

    #[test]
    fn the_gateway_target_has_its_default_port() {
        assert_eq!(gateway_target("https://ctl.example.net:8443/api"), Some(("ctl.example.net".into(), 8443)));
        assert_eq!(gateway_target("https://ctl.example.net"), Some(("ctl.example.net".into(), 443)));
        assert_eq!(gateway_target("http://10.0.0.5"), Some(("10.0.0.5".into(), 80)));
        assert_eq!(gateway_target("https://[fd7a:115c:a1e0::7]:8443"), Some(("fd7a:115c:a1e0::7".into(), 8443)));
        assert_eq!(gateway_target("not a url"), None);
    }

    #[test]
    fn only_a_failed_lookup_and_a_denied_connect_are_enforced() {
        assert_eq!(record(7, 1, false, "denied", None)["enforced"], true);
        assert_eq!(record(7, 1, false, "denied", Some("127.0.0.1:53"))["enforced"], false, "a reachable DNS forwarder is not held");
        assert_eq!(record(7, 1, false, "timeout", None)["enforced"], true, "a dropped SYN can surface as a timeout");
        for (resolved, connect) in [(true, "denied"), (true, "timeout"), (false, "refused"), (false, "connected"), (false, "other:x")] {
            assert_eq!(record(7, 1, resolved, connect, None)["enforced"], false, "{resolved} {connect}");
        }
        let r = record(42, 1794000000, false, "denied", None);
        assert_eq!(r["loopback_dns"], "none");
        assert_eq!(r["pid"], 42);
        assert_eq!(r["lookup"]["name"], CANARY_NAME);
        assert_eq!(r["lookup"]["result"], "failed");
        assert_eq!(r["connect"]["addr"], CANARY_ADDR);
        assert_eq!(r["version"], 1);
    }

    #[test]
    fn the_kernel_refusal_is_told_apart_from_every_other_failure() {
        assert_eq!(connect_result(&Err(io::Error::from_raw_os_error(libc::EPERM))), "denied");
        assert_eq!(connect_result(&Err(io::Error::from_raw_os_error(libc::EACCES))), "denied");
        assert_eq!(connect_result(&Err(io::Error::from(io::ErrorKind::ConnectionRefused))), "refused");
        assert_eq!(connect_result(&Err(io::Error::from(io::ErrorKind::TimedOut))), "timeout");
        assert_eq!(connect_result(&Ok(())), "connected");
        assert!(connect_result(&Err(io::Error::from_raw_os_error(libc::ENETUNREACH))).starts_with("other:"));
    }

    #[test]
    fn the_canaries_never_point_inside_the_allowlist() {
        let a: SocketAddr = CANARY_ADDR.parse().unwrap();
        assert!(a.ip().is_loopback() && a.ip().to_string() != "127.0.0.1", "loopback, never a packet off the host, and outside the allowlist (127.0.0.1/32)");
        assert_eq!(CANARY_NAME, "example.com", "the IANA example domain: harmless if it ever does leave");
    }

    #[test]
    fn the_record_lands_world_readable_and_whole() {
        let dir = std::env::temp_dir().join(format!("noo-egress-selftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_into(&dir, &record(9, 1, false, "denied", None)).unwrap();
        let back: Value = serde_json::from_slice(&std::fs::read(dir.join("egress.json")).unwrap()).unwrap();
        assert_eq!(back["enforced"], true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("egress.json")).unwrap().permissions().mode() & 0o777, 0o644);
        }
        assert!(!dir.join(".egress.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dns_server_on_reachable_loopback_is_found_and_the_stub_is_not() {
        let head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";
        // systemd-resolved's stub on 127.0.0.53 and 127.0.0.54: outside the allowlist, not reachable.
        let stub = format!("{head}\n  1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 1 2 0\n  2: 3600007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 1 2 0\n");
        assert_eq!(reachable_dns_listener(&stub, ""), None);
        let dnsmasq = format!("{head}\n  1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0\n");
        assert_eq!(reachable_dns_listener(&dnsmasq, "").as_deref(), Some("127.0.0.1:53"));
        let any = format!("{head}\n  1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0\n");
        assert_eq!(reachable_dns_listener(&any, "").as_deref(), Some("0.0.0.0:53"));
        let v6 = format!("{head}\n  1: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1 2 0\n");
        assert_eq!(reachable_dns_listener("", &v6).as_deref(), Some("[::1]:53"));
        let other_port = format!("{head}\n  1: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1 2 0\n");
        assert_eq!(reachable_dns_listener(&other_port, ""), None, "only port 53");
    }
}
