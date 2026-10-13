// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Who holds a node name, and may this enrollee take it?
//!
//! A node's identity in this mesh is its NAME: the enrollment record, the
//! registry row, the certificate CN and the provision bundle are all keyed
//! on it, and "latest redemption wins". So a second machine that enrolled
//! under a name already in use did not get a second node. It took over the
//! first one's records.
//!
//! Found live: Pop!_OS names every install `host8`. A second Pop!_OS box
//! joined over the tailnet, its device was still called `host8`, which is
//! also the controller's own node name. Its enrollment row became "host8's
//! record", and the next provision of the controller re-issued the
//! controller's certificate from it: the other machine's address, none of
//! the controller names, and a bundle encrypted to the other machine's key.
//!
//! The rule: a name is held by whatever machine the gateway already knows
//! under it (its latest live enrollment, else its registry row; the
//! controller's own node is held by the controller even with neither). A
//! claim on a held name is refused unless the evidence says it is the SAME
//! machine. Nothing is ever merged. The enrollee renames, or the operator
//! forgets the old record first.

use serde_json::Value;

/// What the gateway knows about the machine that holds a name now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameHolder {
    /// Addresses that machine is known by: its enrollment's recorded
    /// address, its registry row's `ip_address`, its `agent_url` host.
    pub addrs: Vec<String>,
    /// Its machine fingerprint from enrollment facts (`facts.machine_fp`),
    /// when it enrolled with a client that reports one.
    pub machine_fp: Option<String>,
    /// The name is this controller's own node.
    pub controller: bool,
}

/// The machine asking for the name.
#[derive(Debug, Clone, Copy)]
pub struct Claimant<'a> {
    /// The address recorded for it (tailnet address when it reported one).
    pub addr: &'a str,
    pub machine_fp: Option<&'a str>,
}

/// `facts.machine_fp` when it is a plausible fingerprint (hex, 16–128).
pub fn machine_fp_of(facts: Option<&Value>) -> Option<String> {
    let fp = facts?.get("machine_fp")?.as_str()?.trim();
    ((16..=128).contains(&fp.len()) && fp.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| fp.to_ascii_lowercase())
}

/// The host of an `agent_url` like `https://100.64.0.2:8081`.
fn url_host(u: &str) -> Option<String> {
    let rest = u.trim().split_once("://").map(|(_, r)| r).unwrap_or(u.trim());
    let hostport = rest.split('/').next().unwrap_or("");
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport),
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// `None` = the claimant may take `name`. `Some(msg)` = refuse, and `msg`
/// says why and what to do. Pure: every input is passed in.
pub fn conflict(name: &str, holder: &NameHolder, claimant: &Claimant<'_>) -> Option<String> {
    let holder_known = !holder.addrs.is_empty() || holder.machine_fp.is_some();
    if !holder_known && !holder.controller {
        return None; // a free name
    }
    // Same machine? The fingerprint decides when both sides have one. An
    // address match decides otherwise. The controller's own name is held
    // to the address as well: it never moves its own enrollment.
    let same_fp = match (holder.machine_fp.as_deref(), claimant.machine_fp) {
        (Some(h), Some(c)) => Some(h.eq_ignore_ascii_case(c)),
        _ => None,
    };
    let same_addr = holder.addrs.iter().any(|a| a == claimant.addr);
    let same_machine = match same_fp {
        Some(false) => false,
        Some(true) => !holder.controller || same_addr,
        None => same_addr,
    };
    if same_machine {
        return None;
    }
    let rename = "Give this machine its own name and enroll again: `sudo hostnamectl set-hostname <unique-name>` \
         (on the tailnet lane also `sudo tailscale set --hostname=<unique-name>`), or enroll with a token \
         bound to a unique name (`noo cluster bootstrap-token create --node <unique-name>`).";
    if holder.controller {
        return Some(format!(
            "the node name '{name}' is this controller's own node; a different machine \
             ({}) cannot enroll under it. {rename}",
            claimant.addr
        ));
    }
    let held_by = if holder.addrs.is_empty() {
        "another machine".to_string()
    } else {
        format!("another machine ({})", holder.addrs.join(", "))
    };
    Some(format!(
        "the node name '{name}' is already held by {held_by}; this enrollment ({}) would take over its \
         records, so it is refused. {rename} If this IS the same machine re-enrolling from a new \
         address, remove the old record first: `noo cluster forget {name}`.",
        claimant.addr
    ))
}

/// Read who holds `name` now. `exclude_token` is the token row being
/// redeemed (its own row is not a prior holder). Case-insensitive, as
/// hostnames are.
pub async fn holder(
    db: &sqlx::PgPool,
    name: &str,
    exclude_token: Option<uuid::Uuid>,
) -> Result<NameHolder, sqlx::Error> {
    let mut h = NameHolder {
        controller: crate::self_node::self_node_id().is_some_and(|s| s.eq_ignore_ascii_case(name)),
        ..Default::default()
    };
    let push = |v: &mut Vec<String>, a: Option<String>| {
        if let Some(a) = a.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            if !v.contains(&a) {
                v.push(a);
            }
        }
    };
    let enrolled: Option<(Option<String>, Option<Value>)> = sqlx::query_as(
        "SELECT used_by_ip, facts FROM noo_bootstrap_tokens \
         WHERE lower(node_name) = lower($1) AND used_at IS NOT NULL AND NOT revoked \
           AND ($2::uuid IS NULL OR id <> $2) \
         ORDER BY used_at DESC LIMIT 1",
    )
    .bind(name)
    .bind(exclude_token)
    .fetch_optional(db)
    .await?;
    if let Some((ip, facts)) = enrolled {
        push(&mut h.addrs, ip);
        h.machine_fp = machine_fp_of(facts.as_ref());
    }
    let registered: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT ip_address, agent_url FROM cluster_nodes WHERE lower(node_id) = lower($1) LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await?;
    if let Some((ip, agent_url)) = registered {
        push(&mut h.addrs, ip);
        push(&mut h.addrs, agent_url.as_deref().and_then(url_host));
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holder(addrs: &[&str], fp: Option<&str>, controller: bool) -> NameHolder {
        NameHolder {
            addrs: addrs.iter().map(|s| s.to_string()).collect(),
            machine_fp: fp.map(str::to_string),
            controller,
        }
    }

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// The live case, exactly: the controller's own node is `host8` and
    /// is registered at its tailnet address; a second machine whose
    /// tailnet device is also called `host8` asks for the name. Refused,
    /// and nothing about the controller's record changes.
    #[test]
    fn a_second_host8_cannot_take_the_controllers_name() {
        let h = holder(&["100.64.0.1"], None, true);
        let c = Claimant { addr: "100.64.0.2", machine_fp: Some(FP_B) };
        let msg = conflict("host8", &h, &c).expect("refused");
        assert!(msg.contains("'host8' is this controller's own node"), "{msg}");
        assert!(msg.contains("100.64.0.2"), "{msg}");
        assert!(msg.contains("hostnamectl set-hostname"), "{msg}");
        assert!(!msg.contains("noo cluster forget"), "never suggest forgetting the controller: {msg}");
    }

    /// The controller's own name with nothing on record (no registry row
    /// yet) is still the controller's.
    #[test]
    fn the_controllers_name_is_held_even_with_no_record() {
        let h = holder(&[], None, true);
        let c = Claimant { addr: "100.64.0.2", machine_fp: None };
        assert!(conflict("host8", &h, &c).is_some());
    }

    /// The controller enrolling its OWN node from its own address is the
    /// same machine.
    #[test]
    fn the_controller_itself_may_claim_its_name() {
        let h = holder(&["100.64.0.1"], None, true);
        let c = Claimant { addr: "100.64.0.1", machine_fp: Some(FP_A) };
        assert_eq!(conflict("host8", &h, &c), None);
        // A matching fingerprint from another address is NOT enough for the
        // controller's name (a cloned controller VM shares its machine-id).
        let h = holder(&["100.64.0.1"], Some(FP_A), true);
        let c = Claimant { addr: "100.64.0.2", machine_fp: Some(FP_A) };
        assert!(conflict("host8", &h, &c).is_some());
    }

    #[test]
    fn a_free_name_is_free() {
        let c = Claimant { addr: "100.64.0.9", machine_fp: None };
        assert_eq!(conflict("host9", &NameHolder::default(), &c), None);
    }

    /// Two workers, same hostname, different machines: refused, with the
    /// forget hint for the genuine re-enroll case.
    #[test]
    fn a_worker_name_held_by_another_machine_is_refused() {
        let h = holder(&["100.64.0.5"], Some(FP_A), false);
        let c = Claimant { addr: "100.64.0.6", machine_fp: Some(FP_B) };
        let msg = conflict("ubuntu", &h, &c).expect("refused");
        assert!(msg.contains("already held by another machine (100.64.0.5)"), "{msg}");
        assert!(msg.contains("noo cluster forget ubuntu"), "{msg}");
        // Different fingerprints win over a shared address (a reused DHCP
        // lease, a NAT'd peer).
        let c = Claimant { addr: "100.64.0.5", machine_fp: Some(FP_B) };
        assert!(conflict("ubuntu", &h, &c).is_some());
    }

    /// The same machine re-enrolling is not a collision: by fingerprint
    /// even from a new address, by address when either side predates the
    /// fingerprint.
    #[test]
    fn the_same_worker_re_enrolling_is_allowed() {
        let h = holder(&["100.64.0.5"], Some(FP_A), false);
        let c = Claimant { addr: "100.64.0.77", machine_fp: Some(FP_A) };
        assert_eq!(conflict("ubuntu", &h, &c), None);
        let h = holder(&["100.64.0.5"], None, false);
        let c = Claimant { addr: "100.64.0.5", machine_fp: Some(FP_A) };
        assert_eq!(conflict("ubuntu", &h, &c), None);
        let c = Claimant { addr: "100.64.0.6", machine_fp: Some(FP_A) };
        assert!(conflict("ubuntu", &h, &c).is_some(), "no fingerprint on record: the address decides");
    }

    #[test]
    fn fingerprints_and_agent_hosts_parse() {
        let f = serde_json::json!({"machine_fp": FP_A.to_uppercase()});
        assert_eq!(machine_fp_of(Some(&f)).as_deref(), Some(FP_A));
        assert_eq!(machine_fp_of(Some(&serde_json::json!({"machine_fp": "short"}))), None);
        assert_eq!(machine_fp_of(Some(&serde_json::json!({"machine_fp": "zz".repeat(16)}))), None);
        assert_eq!(machine_fp_of(None), None);
        assert_eq!(url_host("https://100.64.0.2:8081").as_deref(), Some("100.64.0.2"));
        assert_eq!(url_host("https://[fd7a::1]:8081/x").as_deref(), Some("fd7a::1"));
        assert_eq!(url_host("http://box").as_deref(), Some("box"));
        assert_eq!(url_host(""), None);
    }
}
