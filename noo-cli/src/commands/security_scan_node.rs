// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! `noo security scan` on an ENROLLED NODE.
//!
//! A node has no `~/.noo` install: no `.env`, no secret store, no gateway.
//! The controller checks (JWT secret, Redis password, Grafana, ...) describe
//! an install that is not there, so running them on a node reports phantom
//! CRITICALs and misses the node's real surfaces. This module scans those
//! instead: the node PKI under `/etc/noo/pki`, the agent's environment file,
//! the birth key and the agent's systemd unit.
//!
//! Everything is split into FACTS (gathered, impure) and a REPORT (pure over
//! the facts). A surface the scan could not read is listed as "not checked",
//! never as fine: the agent's env file is `0600 root`, so a non-root scan can
//! stat it but not read it, and says exactly that.

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use super::security_local::Finding;

pub(crate) const NODE_PKI_DIR: &str = "/etc/noo/pki";
pub(crate) const NODE_AGENT_ENV: &str = "/etc/noo-node-agent.env";
pub(crate) const NODE_BIRTH_KEY: &str = "/etc/noo/birth.key";
pub(crate) const NODE_AGENT_UNIT: &str = "/etc/systemd/system/noo-node-agent.service";

/// Controller-only rows. Named in the output so nobody reads their absence
/// as a pass.
pub(crate) const NOT_APPLICABLE_ON_A_NODE: &[&str] = &[
    "JWT Secret",
    "Cluster Secret",
    "Controller Secret",
    "Node Agent Token (controller copy)",
    "Redis Password",
    "TLS (gateway listener)",
    "Grafana Password",
    "Audit Key",
    "mTLS Enforcement (gateway)",
    "CSP",
    "Exec Approval",
    "Escape Hatches (gateway env)",
    "Secrets At Rest (.env / env.sops)",
    "Admin Password",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeFileFact {
    pub path: String,
    pub is_dir: bool,
    /// Permission bits only (`& 0o7777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct NodeFacts {
    /// Everything readable under the PKI dir (the dir itself included).
    pub pki: Vec<NodeFileFact>,
    /// Paths under the PKI dir that could not be listed, with the reason.
    pub pki_unreadable: Vec<String>,
    pub pki_root_missing: bool,
    pub agent_env_stat: Option<NodeFileFact>,
    /// The env file's text, or why it could not be read.
    pub agent_env_text: Result<String, String>,
    pub birth_key: Option<NodeFileFact>,
    /// The agent unit (plus drop-ins), or why it could not be read.
    pub unit: Result<String, String>,
}

#[derive(Debug, Default)]
pub(crate) struct NodeReport {
    pub findings: Vec<Finding>,
    /// Surfaces read and judged (so "checked" is a claim about evidence).
    pub checked: Vec<String>,
    /// Surfaces that could not be read: never a pass.
    pub not_checked: Vec<String>,
}

fn fact(path: &Path) -> Option<NodeFileFact> {
    let md = std::fs::symlink_metadata(path).ok()?;
    Some(NodeFileFact {
        path: path.display().to_string(),
        is_dir: md.is_dir(),
        mode: md.mode() & 0o7777,
        uid: md.uid(),
        gid: md.gid(),
    })
}

fn walk(dir: &Path, facts: &mut Vec<NodeFileFact>, unreadable: &mut Vec<String>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            unreadable.push(format!("{} ({})", dir.display(), e));
            return;
        }
    };
    for entry in rd.flatten() {
        let p = entry.path();
        // A symlink's own mode is always 0777: judge what it points at only
        // if it is listed in its own right, never the link.
        if entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        if let Some(f) = fact(&p) {
            let is_dir = f.is_dir;
            facts.push(f);
            if is_dir {
                walk(&p, facts, unreadable);
            }
        }
    }
}

/// Read the node's surfaces. Never fails: what cannot be read is recorded.
pub(crate) fn gather_node_facts() -> NodeFacts {
    let pki_root = Path::new(NODE_PKI_DIR);
    let mut pki = Vec::new();
    let mut pki_unreadable = Vec::new();
    let pki_root_missing = !pki_root.exists();
    if !pki_root_missing {
        if let Some(f) = fact(pki_root) {
            pki.push(f);
        }
        walk(pki_root, &mut pki, &mut pki_unreadable);
    }
    let mut unit = std::fs::read_to_string(NODE_AGENT_UNIT).map_err(|e| format!("{NODE_AGENT_UNIT}: {e}"));
    if let Ok(text) = unit.as_mut() {
        if let Ok(rd) = std::fs::read_dir(format!("{NODE_AGENT_UNIT}.d")) {
            let mut confs: Vec<_> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "conf")).collect();
            confs.sort();
            for c in confs {
                if let Ok(t) = std::fs::read_to_string(&c) {
                    text.push('\n');
                    text.push_str(&t);
                }
            }
        }
    }
    NodeFacts {
        pki,
        pki_unreadable,
        pki_root_missing,
        agent_env_stat: fact(Path::new(NODE_AGENT_ENV)),
        agent_env_text: std::fs::read_to_string(NODE_AGENT_ENV).map_err(|e| e.to_string()),
        birth_key: fact(Path::new(NODE_BIRTH_KEY)),
        unit,
    }
}

fn is_private_key(path: &str) -> bool {
    path.ends_with(".key")
}

/// The last `Key=Value` in the unit's text (drop-ins are appended, so the
/// last assignment wins, as systemd resolves it).
fn unit_value<'a>(unit: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    unit.lines().rev().map(str::trim).find_map(|l| l.strip_prefix(prefix.as_str())).map(str::trim)
}

/// Judge the facts. Pure.
pub(crate) fn node_report(f: &NodeFacts) -> NodeReport {
    let mut r = NodeReport::default();

    // ── PKI ─────────────────────────────────────────────────────────────
    if f.pki_root_missing {
        r.not_checked.push(format!("{NODE_PKI_DIR}: does not exist (is this node enrolled?)"));
    } else {
        let exposed: Vec<String> = f
            .pki
            .iter()
            .filter(|x| !x.is_dir && is_private_key(&x.path) && x.mode & 0o007 != 0)
            .map(|x| format!("{} {:04o}", x.path, x.mode))
            .collect();
        if !exposed.is_empty() {
            r.findings.push((
                "CRITICAL",
                "Node PKI Key Modes",
                format!("{} private key(s) readable by every local user: {} — chmod 640 and chgrp noo-agent (root: sudo chmod o-rwx <key>)", exposed.len(), exposed.join(", ")),
            ));
        }
        let writable: Vec<String> = f
            .pki
            .iter()
            .filter(|x| x.mode & 0o022 != 0)
            .map(|x| format!("{} {:04o}", x.path, x.mode))
            .collect();
        if !writable.is_empty() {
            r.findings.push((
                "HIGH",
                "Node PKI Writable",
                format!("group- or world-writable PKI entries: {} — anyone with write access can swap the CA or a leaf; chmod go-w", writable.join(", ")),
            ));
        }
        let foreign: Vec<String> = f.pki.iter().filter(|x| x.uid != 0).map(|x| format!("{} (uid {})", x.path, x.uid)).collect();
        if !foreign.is_empty() {
            r.findings.push((
                "MEDIUM",
                "Node PKI Ownership",
                format!("not root-owned: {} — the node PKI is provisioned root:noo-agent; chown root", foreign.join(", ")),
            ));
        }
        if f.pki_unreadable.is_empty() {
            r.checked.push(format!("{NODE_PKI_DIR}: {} entries, modes and ownership", f.pki.len()));
        } else {
            r.not_checked.push(format!(
                "{NODE_PKI_DIR}: could not list {} — run as root to cover it",
                f.pki_unreadable.join("; ")
            ));
            if !f.pki.is_empty() {
                r.checked.push(format!("{NODE_PKI_DIR}: {} readable entries, modes and ownership", f.pki.len()));
            }
        }
    }

    // ── agent env file ──────────────────────────────────────────────────
    match &f.agent_env_stat {
        None => r.not_checked.push(format!("{NODE_AGENT_ENV}: not present (a macOS node, or not provisioned)")),
        Some(st) => {
            if st.mode & 0o077 != 0 {
                r.findings.push((
                    "HIGH",
                    "Node Agent Env",
                    format!("{NODE_AGENT_ENV} is {:04o}: it holds the agent's credentials and must be 0600 root — chmod 600 {NODE_AGENT_ENV}", st.mode),
                ));
            }
            if st.uid != 0 {
                r.findings.push((
                    "HIGH",
                    "Node Agent Env",
                    format!("{NODE_AGENT_ENV} is owned by uid {}, not root — chown root:root {NODE_AGENT_ENV}", st.uid),
                ));
            }
            r.checked.push(format!("{NODE_AGENT_ENV}: mode {:04o}, owner uid {}", st.mode, st.uid));
            match &f.agent_env_text {
                Ok(text) => {
                    let stale: Vec<&str> = ["NATS_USER", "NATS_PASSWORD"]
                        .into_iter()
                        .filter(|k| {
                            text.lines().any(|l| {
                                l.trim().strip_prefix(&format!("{k}=")).is_some_and(|v| !v.trim().trim_matches('"').is_empty())
                            })
                        })
                        .collect();
                    if !stale.is_empty() {
                        r.findings.push((
                            "LOW",
                            "Retired NATS Credential",
                            format!("{} still set in {NODE_AGENT_ENV} — RETIRED and inert (the agent never presents it); re-provision from the controller to drop it: noo cluster provision <node>", stale.join(", ")),
                        ));
                    }
                    r.checked.push(format!("{NODE_AGENT_ENV}: contents (retired NATS names)"));
                }
                Err(why) => r.not_checked.push(format!(
                    "{NODE_AGENT_ENV}: contents not read ({why}) — run as root to check for a stale NATS_USER"
                )),
            }
        }
    }

    // ── birth key ───────────────────────────────────────────────────────
    match &f.birth_key {
        None => r.not_checked.push(format!("{NODE_BIRTH_KEY}: not present")),
        Some(st) => {
            if st.mode & 0o077 != 0 {
                r.findings.push((
                    "CRITICAL",
                    "Birth Key",
                    format!("{NODE_BIRTH_KEY} is {:04o}: it is this node's enrollment identity and must be 0600 root — chmod 600 {NODE_BIRTH_KEY}", st.mode),
                ));
            }
            if st.uid != 0 {
                r.findings.push((
                    "HIGH",
                    "Birth Key",
                    format!("{NODE_BIRTH_KEY} is owned by uid {}, not root — chown root:root {NODE_BIRTH_KEY}", st.uid),
                ));
            }
            r.checked.push(format!("{NODE_BIRTH_KEY}: mode {:04o}, owner uid {}", st.mode, st.uid));
        }
    }

    // ── unit hardening ──────────────────────────────────────────────────
    match &f.unit {
        Err(why) => r.not_checked.push(format!("node-agent unit not read ({why}) — a macOS node uses launchd, which this scan does not read")),
        Ok(text) => {
            let user = unit_value(text, "User").unwrap_or("");
            if user.is_empty() || user == "root" || user == "0" {
                r.findings.push((
                    "HIGH",
                    "Node Agent Unit",
                    "noo-node-agent.service runs as root (no User=) — the agent is meant to run as noo-agent; re-provision: noo cluster provision <node>".into(),
                ));
            }
            if !unit_value(text, "NoNewPrivileges").is_some_and(super::security_local::flag_is_on) {
                r.findings.push((
                    "MEDIUM",
                    "Node Agent Unit",
                    "noo-node-agent.service lacks NoNewPrivileges=true — re-provision: noo cluster provision <node>".into(),
                ));
            }
            r.checked.push("noo-node-agent.service: User= and NoNewPrivileges=".into());
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, mode: u32, uid: u32) -> NodeFileFact {
        NodeFileFact { path: path.into(), is_dir: false, mode, uid, gid: 0 }
    }

    fn healthy() -> NodeFacts {
        NodeFacts {
            pki: vec![
                NodeFileFact { path: "/etc/noo/pki".into(), is_dir: true, mode: 0o755, uid: 0, gid: 0 },
                file("/etc/noo/pki/ca.crt", 0o644, 0),
                file("/etc/noo/pki/nodes/n/node.key", 0o640, 0),
            ],
            pki_unreadable: vec![],
            pki_root_missing: false,
            agent_env_stat: Some(file(NODE_AGENT_ENV, 0o600, 0)),
            agent_env_text: Ok("NOO_NODE_ID=n\n".into()),
            birth_key: Some(file(NODE_BIRTH_KEY, 0o600, 0)),
            unit: Ok("[Service]\nUser=noo-agent\nNoNewPrivileges=true\n".into()),
        }
    }

    fn checks(r: &NodeReport) -> Vec<&'static str> {
        r.findings.iter().map(|(_, c, _)| *c).collect()
    }

    #[test]
    fn a_healthy_node_has_no_findings_and_says_what_it_read() {
        let r = node_report(&healthy());
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert!(r.not_checked.is_empty());
        assert!(r.checked.iter().any(|c| c.contains("/etc/noo/pki")));
    }

    #[test]
    fn world_readable_keys_and_loose_modes_are_findings() {
        let mut f = healthy();
        f.pki.push(file("/etc/noo/pki/nodes/n/other.key", 0o644, 0));
        f.agent_env_stat = Some(file(NODE_AGENT_ENV, 0o644, 0));
        f.birth_key = Some(file(NODE_BIRTH_KEY, 0o640, 0));
        let r = node_report(&f);
        let c = checks(&r);
        assert!(c.contains(&"Node PKI Key Modes") && c.contains(&"Node Agent Env") && c.contains(&"Birth Key"), "{c:?}");
        assert!(r.findings.iter().any(|(s, c, _)| *s == "CRITICAL" && *c == "Birth Key"));
    }

    #[test]
    fn group_readable_keys_are_the_provisioned_state_not_a_finding() {
        let r = node_report(&healthy());
        assert!(!checks(&r).contains(&"Node PKI Key Modes"));
    }

    #[test]
    fn an_unreadable_surface_is_never_a_pass() {
        let mut f = healthy();
        f.pki_unreadable = vec!["/etc/noo/pki/nodes (Permission denied)".into()];
        f.agent_env_text = Err("Permission denied".into());
        f.unit = Err("no such file".into());
        let r = node_report(&f);
        assert_eq!(r.not_checked.len(), 3, "{:?}", r.not_checked);
        assert!(r.not_checked.iter().any(|n| n.contains("run as root")));
        // and the unreadable env contents are not reported as "checked"
        assert!(!r.checked.iter().any(|c| c.contains("contents")));
    }

    #[test]
    fn a_stale_legacy_nats_user_is_flagged_only_when_it_has_a_value() {
        let mut f = healthy();
        f.agent_env_text = Ok("NATS_USER=\nNATS_PASSWORD=\n".into());
        assert!(!checks(&node_report(&f)).contains(&"Retired NATS Credential"));
        f.agent_env_text = Ok("NATS_USER=shared\n".into());
        assert!(checks(&node_report(&f)).contains(&"Retired NATS Credential"));
    }

    #[test]
    fn unit_hardening_is_read_from_the_unit() {
        let mut f = healthy();
        f.unit = Ok("[Service]\nExecStart=/x\n".into());
        let c = checks(&node_report(&f));
        assert_eq!(c.iter().filter(|c| **c == "Node Agent Unit").count(), 2, "{c:?}");
        f.unit = Ok("[Service]\nUser=root\nNoNewPrivileges=true\n".into());
        assert_eq!(checks(&node_report(&f)), vec!["Node Agent Unit"]);
        // a drop-in appended later wins
        f.unit = Ok("[Service]\nUser=root\nNoNewPrivileges=true\n[Service]\nUser=noo-agent\n".into());
        assert!(node_report(&f).findings.is_empty());
    }

    #[test]
    fn a_missing_pki_dir_is_not_checked_rather_than_fine() {
        let mut f = healthy();
        f.pki.clear();
        f.pki_root_missing = true;
        let r = node_report(&f);
        assert!(r.not_checked.iter().any(|n| n.contains(NODE_PKI_DIR)));
    }
}
