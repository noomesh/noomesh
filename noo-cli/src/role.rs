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
/// Where this box's own node name can be read, in the order the name is
/// taken. ONE chain for both questions: what this box's node is CALLED
/// ([`self_node_name`]) and whether a name IS this box's node
/// ([`is_self_node`]). Until 2026-11-10 they were two chains over different
/// sources (the name from NODE_ID in `envfile::repo_root()/.env` or
/// `/etc/hostname`; the match from `uname -n` or NODE_ID in
/// `standalone::default_home()/.env`), so a WSL controller could name its
/// node one way and fail to recognise it: `noo upgrade --all` staged it
/// FIRST as a remote node (outside tester, 0.6.21), and every self-node
/// lane missed it.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct SelfIdentity {
    /// `/etc/noo/node-name` (written by prep-host for this box's node).
    pub node_name_file: Option<String>,
    /// NODE_ID in `envfile::repo_root()/.env`, then in
    /// `standalone::default_home()/.env` (the same file when they agree).
    pub env_node_ids: Vec<String>,
    /// `/etc/hostname`: the old name chain's last source, so it stays
    /// ahead of `uname -n` and no existing self node is renamed.
    pub etc_hostname: Option<String>,
    /// `uname -n`: on WSL the Windows machine name, set at boot, which can
    /// differ from `/etc/hostname`. The old match's source.
    pub uname_n: Option<String>,
}

impl SelfIdentity {
    /// This machine's sources, read now.
    pub(crate) fn read() -> Self {
        let t = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let mut env_node_ids = Vec::new();
        for root in [crate::envfile::repo_root(), crate::onboard::standalone::default_home()] {
            if let Some(id) = t(Some(crate::onboard::env::read_env_key(&root.join(".env"), "NODE_ID"))) {
                if !env_node_ids.contains(&id) {
                    env_node_ids.push(id);
                }
            }
        }
        let uname_n = std::process::Command::new("uname").arg("-n").output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
        SelfIdentity {
            node_name_file: t(read_trimmed(Path::new(NODE_NAME))),
            env_node_ids,
            etc_hostname: t(std::fs::read_to_string("/etc/hostname").ok()),
            uname_n: t(uname_n),
        }
    }

    /// Every name this box answers to, in chain order, each trimmed and
    /// non-empty.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.node_name_file.iter()
            .chain(self.env_node_ids.iter())
            .chain(self.etc_hostname.iter())
            .chain(self.uname_n.iter())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// The node's name: the first source that says one.
    pub(crate) fn name(&self) -> Option<String> {
        self.names().first().map(|s| s.to_string())
    }

    /// Whether `name` is this box's node: any source in the chain, case
    /// folded. Any, not only the first, so the name [`Self::name`] gives is
    /// always recognised AND no name recognised before the merge stops
    /// being recognised (the old match read the marker, `uname -n` and the
    /// standalone NODE_ID; all are still here).
    pub(crate) fn is(&self, name: &str) -> bool {
        let name = name.trim();
        !name.is_empty() && self.names().iter().any(|n| n.eq_ignore_ascii_case(name))
    }
}

/// This controller's own node name: `/etc/noo/node-name`, then NODE_ID in
/// the install's `.env` (either root), then `/etc/hostname`, then
/// `uname -n`. See [`SelfIdentity`].
pub fn self_node_name() -> Option<String> {
    SelfIdentity::read().name()
}

/// Is `name` the node that lives on THIS device — the controller's own
/// node? One answer for every verb that must treat the self-node
/// differently (no tailnet join, no CLI in its bundle, never purge its
/// tailnet, restage it last, adopt the stack's ollama); the operator uses
/// the same commands either way. Same chain as [`self_node_name`].
pub fn is_self_node(name: &str) -> bool {
    SelfIdentity::read().is(name)
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
    &["security", "at-rest", "recovery-key"],
    &["security", "at-rest", "reenroll"],
    &["security", "at-rest", "preflight-firmware"],
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
mod self_identity_tests {
    use super::SelfIdentity;

    fn id(node_name: Option<&str>, env: &[&str], hostname: Option<&str>, uname: Option<&str>) -> SelfIdentity {
        SelfIdentity {
            node_name_file: node_name.map(str::to_string),
            env_node_ids: env.iter().map(|s| s.to_string()).collect(),
            etc_hostname: hostname.map(str::to_string),
            uname_n: uname.map(str::to_string),
        }
    }

    /// The four ways a WSL controller's node went unrecognised (0.6.21,
    /// "Lenovo-P52s"): whatever source named it, the match recognises it.
    #[test]
    fn the_name_this_box_gives_its_node_is_always_recognised() {
        let cases = [
            // (a) NODE_ID only in the checkout's / NOO_REPO_ROOT's .env.
            ("a", id(None, &["Lenovo-P52s"], Some("other"), Some("OTHER"))),
            // (b) /etc/hostname differs from `uname -n`.
            ("b", id(None, &[], Some("Lenovo-P52s"), Some("LENOVO-WSL"))),
            // (c) another HOME: no .env NODE_ID found, only the hostnames.
            ("c", id(None, &[], None, Some("LENOVO-P52S"))),
            // (d) no /etc/noo/node-name (self-prep never completed).
            ("d", id(None, &["Lenovo-P52s"], None, None)),
        ];
        for (why, s) in cases {
            let name = s.name().unwrap_or_else(|| panic!("({why}) no name"));
            assert!(s.is(&name), "({why}) named '{name}' but not recognised: {s:?}");
            assert!(s.is(&name.to_ascii_uppercase()) && s.is(&format!(" {} ", name.to_ascii_lowercase())), "({why}) case and whitespace");
        }
    }

    /// Every source the old match read is still read: nothing recognised
    /// before is dropped (awolf: node-name `awolf`, uname -n `AWOLF`).
    #[test]
    fn every_source_is_recognised_and_the_name_is_the_first() {
        let s = id(Some("awolf"), &["nid-1", "nid-2"], Some("host-file"), Some("AWOLF-UNAME"));
        for n in ["AWOLF", "nid-1", "nid-2", "HOST-FILE", "awolf-uname"] {
            assert!(s.is(n), "{n}");
        }
        assert_eq!(s.name().as_deref(), Some("awolf"));
        assert!(!s.is("pop-os") && !s.is("") && !s.is("   "));
    }

    /// The name chain is the old one: marker, NODE_ID, /etc/hostname; only
    /// then `uname -n` (new), so no existing self node is renamed.
    #[test]
    fn the_name_order_keeps_the_old_name() {
        assert_eq!(id(None, &["nid"], Some("h"), Some("u")).name().as_deref(), Some("nid"));
        assert_eq!(id(None, &[], Some("h"), Some("u")).name().as_deref(), Some("h"));
        assert_eq!(id(None, &[], None, Some("u")).name().as_deref(), Some("u"));
        assert_eq!(id(Some("  "), &[], None, None).name(), None, "blank is no name");
    }

    /// ONE identity chain: is_self_node and both self_node_name entry points
    /// go through SelfIdentity, and no other chain reads the sources.
    #[test]
    fn there_is_one_self_identity_chain() {
        let role = crate::test_src::own_code(include_str!("role.rs"));
        let is_self = crate::test_src::fn_body(&role, "pub fn is_self_node(");
        assert!(is_self.contains("SelfIdentity::read().is(name)"), "{is_self}");
        let named = crate::test_src::fn_body(&role, "pub fn self_node_name(");
        assert!(named.contains("SelfIdentity::read().name()"), "{named}");
        let prov = crate::test_src::own_code(include_str!("commands/provision.rs"));
        let pn = crate::test_src::fn_body(&prov, "pub(crate) fn self_node_name(");
        assert!(pn.contains("crate::role::self_node_name()"), "provision delegates: {pn}");
        // The sources are read in SelfIdentity::read alone. One known
        // exception, not an identity MATCH: `hostname()`, the display name
        // `detect()` gives a prepped node-only box with no marker.
        let read = crate::test_src::fn_body(&role, "pub(crate) fn read(");
        let display = crate::test_src::fn_body(&role, "fn hostname(");
        // Case (a): NODE_ID is read from BOTH .env roots, and both hostnames
        // reach the struct.
        assert!(read.contains("for root in [crate::envfile::repo_root(), crate::onboard::standalone::default_home()]"), "{read}");
        assert!(read.contains("uname_n: t(uname_n)") && read.contains("etc_hostname: t("), "{read}");
        for src in ["\"/etc/hostname\"", "arg(\"-n\")", "\"NODE_ID\""] {
            assert!(read.contains(src), "read() reads {src}");
            assert_eq!(role.matches(src).count(), read.matches(src).count() + display.matches(src).count(),
                "role.rs reads {src} outside SelfIdentity::read");
        }
        for src in ["arg(\"-n\")", "\"/etc/hostname\""] {
            assert!(!pn.contains(src), "provision::self_node_name has its own chain again");
        }
    }
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
