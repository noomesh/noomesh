// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What box is this? The CLI ships to every machine in the mesh — the
//! controller (onboard), every node (enroll), and laptops that only talk to
//! a remote controller — and until 0.3.28 it had no idea which one it was
//! standing on. `noo stack status` on a worker printed fourteen
//! "NOO_APP_DB_PASSWORD not set" warnings (HOST3, 2026-09-01); tab completion
//! on nodes (0.3.27) made every controller-only verb one <Tab> away from that
//! confusion. Detected ONCE here from the markers the install paths already
//! write; every verb that cares asks this module instead of re-deriving.

use crate::Unhandled;
use crate::Globals;
use std::path::{Path, PathBuf};

const NODE_NAME: &str = "/etc/noo/node-name";
const NODE_PREPPED: &str = "/etc/noo/host-prepped";
const NODE_CONTROLLER_URL: &str = "/etc/noo/controller-url";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Controller {
    /// `~/.noo` (or NOO_REPO_ROOT) carrying the `.noo-standalone` marker.
    Standalone(PathBuf),
    /// A source checkout with a live `.env` + `noomesh.yaml` (dev lane).
    Checkout(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub controller_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRole {
    pub controller: Option<Controller>,
    pub node: Option<Node>,
}

impl HostRole {
    /// A node that is NOT also the controller — the shape where
    /// controller-only verbs must refuse instead of stumbling.
    pub fn node_only(&self) -> Option<&Node> {
        if self.controller.is_none() { self.node.as_ref() } else { None }
    }
    pub fn label(&self) -> String {
        match (&self.controller, &self.node) {
            (Some(c), Some(n)) => format!("controller + node '{}' ({})", n.name, where_(c)),
            (Some(c), None) => format!("controller ({})", where_(c)),
            (None, Some(n)) => match &n.controller_url {
                Some(u) => format!("node '{}' → controller {u}", n.name),
                None => format!("node '{}' (controller URL unknown)", n.name),
            },
            (None, None) => "no install on this box (client-only, fresh, or offboarded)".to_string(),
        }
    }
}

fn where_(c: &Controller) -> String {
    match c {
        Controller::Standalone(p) => format!("standalone, {}", p.display()),
        Controller::Checkout(p) => format!("source checkout, {}", p.display()),
    }
}

fn read_trimmed(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Detect from the markers the install paths write. Cheap (a few stats),
/// no network, no sudo — `node-name` and `controller-url` are 644.
/// Is `name` the node that lives on THIS device — the controller's own
/// node? True when it is the enrolled node name here, this host's name,
/// or the NODE_ID the controller install recorded. One answer for every
/// verb that must treat the self-node differently (no tailnet join, no
/// CLI in its bundle, never purge its tailnet, restage it last, adopt the
/// stack's ollama); the operator uses the same commands either way.
pub fn is_self_node(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    if read_trimmed(Path::new(NODE_NAME)).is_some_and(|n| n.eq_ignore_ascii_case(name)) {
        return true;
    }
    if let Ok(o) = std::process::Command::new("uname").arg("-n").output() {
        let h = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !h.is_empty() && h.eq_ignore_ascii_case(name) {
            return true;
        }
    }
    let home = crate::onboard::standalone::default_home();
    let recorded = crate::onboard::env::read_env_key(&home.join(".env"), "NODE_ID");
    !recorded.is_empty() && recorded.trim().eq_ignore_ascii_case(name)
}

pub fn detect() -> HostRole {
    let standalone = crate::onboard::standalone::default_home();
    let controller = if standalone.join(".noo-standalone").is_file() {
        Some(Controller::Standalone(standalone))
    } else {
        let root = crate::envfile::repo_root();
        if root.join(".env").is_file() && root.join("noomesh.yaml").is_file() {
            Some(Controller::Checkout(root))
        } else {
            None
        }
    };
    let node = match read_trimmed(Path::new(NODE_NAME)) {
        Some(name) => Some(Node { name, controller_url: read_trimmed(Path::new(NODE_CONTROLLER_URL)) }),
        None if Path::new(NODE_PREPPED).is_file() => Some(Node {
            name: hostname(),
            controller_url: read_trimmed(Path::new(NODE_CONTROLLER_URL)),
        }),
        None => None,
    };
    HostRole { controller, node }
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname").ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this-host".to_string())
}

/// Verbs that act on the LOCAL stack — meaningless on a node-only box,
/// where the agent is a systemd unit and the stack lives on the controller.
/// Everything else (cluster status, health, chat, rag, heartbeat …) is a
/// gateway client and works from any box that can reach the controller.
const CONTROLLER_ONLY: &[&[&str]] = &[
    &["stack"],
    &["offboard"],
    &["migrate", "export"],
    &["controller"],
    &["security", "at-rest", "create-volume"],
    &["security", "at-rest", "migrate"],
    &["security", "at-rest", "wipe-plaintext"],
    &["security", "pki"],
    &["security", "trust-ca"],
    &["security", "untrust-ca"],
    &["security", "at-rest", "seal"],
    &["security", "at-rest", "finalize"],
    &["db"],
    &["logs"],
];

/// Refuse a controller-only verb on a node-only box with a message that
/// says where the verb DOES run. Returns normally when the verb may proceed.
pub fn gate(g: &Globals, words: &[String]) {
    let hit = CONTROLLER_ONLY.iter().any(|p| {
        words.len() >= p.len() && p.iter().zip(words).all(|(a, b)| a == b)
    });
    if !hit {
        return;
    }
    let role = detect();
    if let Some(n) = role.node_only() {
        let verb = words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
        let target = n.controller_url.as_deref().unwrap_or("the controller");
        crate::output::fail(
            g.json,
            crate::output::ExitCode::Usage,
            "wrong_host_role",
            &format!("this box is node '{}' — `noo {verb}` runs on the controller ({target})", n.name),
            Some("node-side: `noo whoami`, `noo cluster status`, `noo health`; \
                  to leave the mesh: on the controller `noo cluster teardown-node <name>`"),
        );
    }
}

/// Say where the gateway URL came from, in this box's terms.
///
/// `https://localhost:8080` is the right answer on the controller and a
/// symptom on a laptop, so the fallback rung reads differently depending on
/// what the box is. Shared by `noo auth status` and `noo whoami` so the two
/// cannot drift apart.
pub fn gateway_provenance(src: &crate::envfile::GatewaySource) -> String {
    if *src != crate::envfile::GatewaySource::Default {
        return format!("from {}", src.describe());
    }
    // Only two things worth saying, and the second must not over-diagnose:
    // role detection reads the checkout from the cwd, so a controller
    // operator standing in $HOME can miss the controller branch. Naming the
    // MECHANISM ("assumed the gateway is on this box") is true either way;
    // `noo whoami` is where the role itself gets adjudicated.
    if detect().controller.is_some() {
        "the default: this box is the controller, so the gateway is local".to_string()
    } else {
        "the default: nothing set a gateway URL, so the CLI assumed the gateway is on this box"
            .to_string()
    }
}

/// `noo whoami` — the role, the controller this box reports to, the binary.
pub fn whoami(g: &Globals, args: &[String]) -> Result<i32, Unhandled> {
    if !args.is_empty() {
        return Err(Unhandled);
    }
    let role = detect();
    if g.json {
        let ctl = role.controller.as_ref().map(|c| match c {
            Controller::Standalone(p) => serde_json::json!({"kind": "standalone", "home": p}),
            Controller::Checkout(p) => serde_json::json!({"kind": "checkout", "root": p}),
        });
        let node = role.node.as_ref().map(|n| serde_json::json!({"name": n.name, "controller_url": n.controller_url}));
        let (base, from) = crate::envfile::gateway_url_source(&g.gateway_override);
        println!("{}", serde_json::json!({
            "controller": ctl, "node": node, "label": role.label(),
            "gateway": base,
            "gateway_source": from.label(),
            "gateway_source_detail": from.describe(),
            "cli_version": env!("CARGO_PKG_VERSION"),
        }));
        return Ok(0);
    }
    let (base, from) = crate::envfile::gateway_url_source(&g.gateway_override);
    println!("this box: {}", role.label());
    // `noo auth status` points here for "which gateway you are talking to";
    // until 0.3.96 whoami never said. A hint that names a command has to be
    // answerable by that command.
    println!("gateway:  {base}  {}", crate::ui::muted(&gateway_provenance(&from)));
    println!("cli:      noo {}", env!("CARGO_PKG_VERSION"));
    if let Some(n) = role.node_only() {
        println!("here:     noo cluster status · noo health · noo chat  (gateway client verbs)");
        println!("not here: noo stack … · noo offboard · noo controller …  (run on {})",
            n.controller_url.as_deref().unwrap_or("the controller"));
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_names_the_rung_when_something_set_the_url() {
        use crate::envfile::GatewaySource;
        // The three explicit rungs are pure: no box detection, and each one
        // names the thing an operator can go read or unset.
        assert_eq!(gateway_provenance(&GatewaySource::Override), "from --gateway");
        assert_eq!(
            gateway_provenance(&GatewaySource::Env("CONTROLLER_URL")),
            "from $CONTROLLER_URL"
        );
        assert!(gateway_provenance(&GatewaySource::Enrolled).contains("/etc/noo/controller-url"));
    }

    #[test]
    fn the_default_rung_always_explains_itself() {
        // Whatever box the test runs on, the fallback must say "the default"
        // and then why — never bare, because a bare localhost URL is exactly
        // the output an operator cannot act on.
        let d = gateway_provenance(&crate::envfile::GatewaySource::Default);
        assert!(d.starts_with("the default:"), "{d}");
        assert!(d.len() > "the default:".len() + 8, "{d}");
    }

    #[test]
    fn labels_cover_every_shape() {
        let both = HostRole {
            controller: Some(Controller::Standalone(PathBuf::from("/h/.noo"))),
            node: Some(Node { name: "host8".into(), controller_url: None }),
        };
        assert!(both.label().starts_with("controller + node 'host8'"));
        assert!(both.node_only().is_none());
        let node = HostRole {
            controller: None,
            node: Some(Node { name: "host3".into(), controller_url: Some("https://c:8080".into()) }),
        };
        assert_eq!(node.label(), "node 'host3' → controller https://c:8080");
        assert!(node.node_only().is_some());
        let none = HostRole { controller: None, node: None };
        assert!(none.label().contains("no install"));
    }
}
