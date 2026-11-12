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
//! - to connect to [`CANARY_ADDR`] (TEST-NET-1, RFC 5737): under the
//!   allowlist the kernel refuses it with EPERM before a packet exists.
//!
//! It writes the result to [`SELFTEST_FILE`] (world-readable; it holds no
//! secret) with its pid, so the node agent can tell the result belongs to
//! the unit's running process (`MainPID`) and report it in the heartbeat.
//! The directory exists only under the drop-in (`RuntimeDirectory=`); without
//! it nothing is written and the agent reports "unknown", never "enforced".
//!
//! When the unit is NOT restricted, the two canaries do leave the machine: a
//! DNS question for example.com (the IANA reserved example domain) and one
//! SYN towards a TEST-NET address that routes nowhere. Both are harmless by
//! design, and an egress capture shows exactly them on such a node.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

/// The runtime directory the drop-in creates (`RuntimeDirectory=noo-harness`).
pub const SELFTEST_DIR: &str = "/run/noo-harness";
/// The self-test result the node agent reads.
pub const SELFTEST_FILE: &str = "/run/noo-harness/egress.json";
/// A name that must not resolve from inside the unit.
pub const CANARY_NAME: &str = "example.com";
/// An address the unit must not be able to connect to (TEST-NET-1).
pub const CANARY_ADDR: &str = "192.0.2.1:9";
/// Each canary's bound: a refused one answers at once; only a broken
/// enforcement waits this long.
const CANARY_TIMEOUT: Duration = Duration::from_secs(3);

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

/// The self-test record. `enforced` only when the lookup failed AND the
/// kernel denied the connect: either alone is not enough.
pub fn record(pid: u32, started_at: u64, lookup_resolved: bool, connect: &str) -> Value {
    let enforced = !lookup_resolved && connect == "denied";
    json!({
        "version": 1,
        "pid": pid,
        "started_at": started_at,
        "lookup": {"name": CANARY_NAME, "result": if lookup_resolved { "resolved" } else { "failed" }},
        "connect": {"addr": CANARY_ADDR, "result": connect},
        "enforced": enforced,
    })
}

async fn lookup_resolves() -> bool {
    matches!(
        tokio::time::timeout(CANARY_TIMEOUT, tokio::net::lookup_host((CANARY_NAME, 443))).await,
        Ok(Ok(mut addrs)) if addrs.next().is_some()
    )
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

/// Run both canaries and write the record, when the drop-in's runtime
/// directory exists. Returns the record (None: no directory, nothing run).
pub async fn run_at_start() -> Option<Value> {
    let dir = Path::new(SELFTEST_DIR);
    if !dir.is_dir() {
        tracing::warn!("harness: no {SELFTEST_DIR}: this unit carries no egress drop-in, so nothing holds it off the internet (the agent reports egress unknown)");
        return None;
    }
    let resolved = lookup_resolves().await;
    let connect = connect_result(&connect_canary().await);
    let started_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let rec = record(std::process::id(), started_at, resolved, &connect);
    if rec["enforced"] == Value::Bool(true) {
        tracing::info!(lookup = "failed", connect = %connect, "harness: egress held: no internet name resolves and no internet address is reachable");
    } else {
        tracing::error!(lookup = if resolved { "resolved" } else { "failed" }, connect = %connect, "harness: egress NOT held: this unit can reach the internet");
    }
    if let Err(e) = write_into(dir, &rec) {
        tracing::error!(error = %e, file = SELFTEST_FILE, "harness: could not write the egress self-test (the agent reports egress unknown)");
    }
    Some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_failed_lookup_and_a_denied_connect_are_enforced() {
        assert_eq!(record(7, 1, false, "denied")["enforced"], true);
        for (resolved, connect) in [(true, "denied"), (false, "refused"), (false, "timeout"), (false, "connected"), (false, "other:x")] {
            assert_eq!(record(7, 1, resolved, connect)["enforced"], false, "{resolved} {connect}");
        }
        let r = record(42, 1794000000, false, "denied");
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
        assert!(a.ip().to_string().starts_with("192.0.2."), "TEST-NET-1 only: never a private, tailnet or public address");
        assert_eq!(CANARY_NAME, "example.com", "the IANA example domain: harmless if it ever does leave");
    }

    #[test]
    fn the_record_lands_world_readable_and_whole() {
        let dir = std::env::temp_dir().join(format!("noo-egress-selftest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_into(&dir, &record(9, 1, false, "denied")).unwrap();
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
}
