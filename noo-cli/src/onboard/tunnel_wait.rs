//! Onboard's closing verify, and the tunnel the gateway restart just dropped.
//!
//! The converge step restarts the gateway. The node's tunnel redials in 3-11 s
//! and the node's next heartbeat (the agent kicks one on a connect) carries
//! `control_transports.tunnel`; until then the record says `false` and the
//! closing `cluster verify` would WARN "streaming over tunnel: NOT CHECKED".
//! So onboard, and only onboard, waits a bounded 15 s for the record before
//! it runs the verify. `noo cluster verify` itself never waits: it reports
//! what the record says.

use std::time::Duration;

/// How long the closing verify waits for the self node's tunnel to report in.
pub(crate) const TUNNEL_WAIT_SECS: u64 = 15;
/// How often the node record is re-read while waiting.
pub(crate) const TUNNEL_POLL_SECS: u64 = 3;

/// The agent's and the gateway's own spelling of "off": `0|false|off|no`.
pub(crate) fn tunnel_off_value(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no")
}

/// Whether to wait: the record says the tunnel is down (`Some(false)`) and it
/// is not off on purpose. `true` and "no such field" (an older agent) never
/// wait. Pure.
pub(crate) fn should_wait_for_tunnel(advertised: Option<bool>, off_on_purpose: bool) -> bool {
    advertised == Some(false)
}

/// The operator switched the tunnel off: `NOO_AGENT_TUNNEL` (the node's
/// agent) or `NOO_NODE_TUNNEL` (this gateway), in this process, the install's
/// `.env`, or the agent's env file.
pub(crate) fn tunnel_off_on_purpose() -> bool {
    let env_file = |path: &std::path::Path, key: &str| tunnel_off_value(&crate::onboard::env::read_env_key(path, key));
    let var = |key: &str| std::env::var(key).is_ok_and(|v| tunnel_off_value(&v));
    var("NOO_AGENT_TUNNEL")
        || var("NOO_NODE_TUNNEL")
        || env_file(&crate::envfile::repo_root().join(".env"), "NOO_NODE_TUNNEL")
        || env_file(std::path::Path::new(crate::commands::security_scan_node::NODE_AGENT_ENV), "NOO_AGENT_TUNNEL")
}

/// Re-read the record every `poll` until it says true or `limit` has passed.
/// `read` returns the record's `control_transports.tunnel`; `sleep` is the
/// clock. Returns the last value read.
pub(crate) fn wait_for_tunnel(
    limit: Duration,
    poll: Duration,
    mut read: impl FnMut() -> Option<bool>,
    mut sleep: impl FnMut(Duration),
) -> Option<bool> {
    let mut waited = Duration::ZERO;
    let mut last = read();
    while last != Some(true) && waited < limit {
        let step = poll.min(limit - waited);
        sleep(step);
        waited += step;
        last = read();
    }
    last
}

/// The waiting line: the seconds, and why.
pub(crate) fn waiting_line() -> String {
    format!("waiting up to {TUNNEL_WAIT_SECS} s for the node's tunnel to report in (the gateway restarted moments ago)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tunnel_reported_down_and_not_off_on_purpose_is_waited_for() {
        assert!(should_wait_for_tunnel(Some(false), false));
    }

    #[test]
    fn a_tunnel_switched_off_on_purpose_is_not_waited_for() {
        assert!(!should_wait_for_tunnel(Some(false), true));
    }

    #[test]
    fn a_tunnel_that_is_up_or_unreported_is_not_waited_for() {
        assert!(!should_wait_for_tunnel(Some(true), false));
        assert!(!should_wait_for_tunnel(None, false));
    }

    #[test]
    fn the_off_spellings_are_the_agents_and_the_gateways() {
        for v in ["0", "false", "OFF", " no "] {
            assert!(tunnel_off_value(v), "{v}");
        }
        for v in ["1", "on", "true", "", "later"] {
            assert!(!tunnel_off_value(v), "{v}");
        }
    }

    #[test]
    fn the_wait_stops_when_the_record_turns_true_and_never_passes_fifteen_seconds() {
        let mut reads = 0;
        let mut slept = Duration::ZERO;
        let got = wait_for_tunnel(Duration::from_secs(TUNNEL_WAIT_SECS), Duration::from_secs(TUNNEL_POLL_SECS),
            || { reads += 1; Some(reads >= 3) }, |d| slept += d);
        assert_eq!((got, slept), (Some(true), Duration::from_secs(2 * TUNNEL_POLL_SECS)));
        let mut slept = Duration::ZERO;
        let got = wait_for_tunnel(Duration::from_secs(TUNNEL_WAIT_SECS), Duration::from_secs(TUNNEL_POLL_SECS),
            || Some(false), |d| slept += d);
        assert_eq!((got, slept), (Some(false), Duration::from_secs(TUNNEL_WAIT_SECS)));
    }

    #[test]
    fn the_waiting_line_names_the_seconds() {
        assert!(waiting_line().contains("waiting up to 15 s for the node's tunnel to report in"));
    }

    /// The wait sits in onboard, before its closing verify, and `noo cluster
    /// verify` itself never learns it.
    #[test]
    fn the_wait_is_before_onboards_closing_verify_and_not_in_cluster_verify() {
        let onboard = include_str!("mod.rs");
        let wait = onboard.find("        wait_for_self_node_tunnel(ctx);\n").expect("onboard waits");
        let verify = onboard.find("match crate::commands::cluster_verify(ctx.g, &args) {").expect("onboard verifies");
        assert!(wait < verify, "the wait comes before the closing verify");
        assert!(!include_str!("../commands/cluster_verify.rs").contains("tunnel_wait"), "verify itself never waits");
    }
}
