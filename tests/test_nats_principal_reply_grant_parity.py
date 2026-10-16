# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Each remote principal's static reply grant IS the inbox the gateway addresses it on (i69, i70).

`allow_responses` entries live in a per-connection map that nats-server
replaces on every config reload, so a reply to a request delivered before a
SIGHUP was refused (`Publish Violation` on `_INBOX_gw.…`). The fix is a
static publish grant on the reply inbox — scoped per principal: the worker
on `_INBOX_gw.worker.>`, each add-on on `_INBOX_gw.<name>.>` (trellion,
trellion_intel), each node on `_INBOX_gw.node.<token>.>`. Two crates,
no shared source: `noo-cli` renders the grants, `gateway-rust` picks the
reply inboxes. If either moves alone the replies are refused again —
silently, because NATS reports a refused publish asynchronously.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRANTS = ROOT / "noo-cli/src/commands/nats_users.rs"
GW = ROOT / "gateway-rust/src"
GW_CREDS = GW / "nats_credentials.rs"


def _const(path: Path, name: str) -> str:
    m = re.search(rf'pub(?:\(crate\))? const {name}: &str = "([^"]+)";', path.read_text())
    assert m, f"{name} not found in {path.relative_to(ROOT)}"
    return m.group(1)


def _role_block(role: str) -> str:
    text = GRANTS.read_text()
    m = re.search(rf"Role::{role} => format!\((.*?)\n        \),", text, re.S)
    assert m, f"Role::{role} grant not found in perms_for"
    return m.group(1)


def _publish_allow(block: str) -> str:
    pub = block.split("subscribe:")[0]
    m = re.search(r"allow: \[(.*?)\]", pub)
    assert m, f"no publish allow list in:\n{block}"
    return m.group(1)


def test_the_worker_reply_grant_is_the_worker_inbox():
    prefix = _const(GW_CREDS, "WORKER_REPLY_PREFIX")
    grant = _const(GRANTS, "WORKER_REPLY_INBOX")
    assert grant == f"{prefix}.>", (
        f"the worker may publish replies on {grant!r} but the gateway addresses it on {prefix!r}.*: "
        "every worker reply that straddles a NATS reload is refused"
    )
    assert prefix.startswith(_const(GW_CREDS, "INBOX_PREFIX") + "."), prefix


def test_the_node_reply_root_is_the_same_in_both_crates():
    gw = _const(GW_CREDS, "NODE_REPLY_ROOT")
    assert gw == _const(GRANTS, "NODE_REPLY_ROOT")
    assert gw.startswith(_const(GW_CREDS, "INBOX_PREFIX") + "."), gw


def test_the_gateway_connects_with_its_prefix():
    # The scoped inboxes are sub-prefixes of it: the gateway's own `>`
    # subscribe covers them, and its default inbox stays separate.
    assert "crate::nats_credentials::INBOX_PREFIX" in (GW / "state.rs").read_text()


def test_each_addon_reply_grant_is_its_gateway_inbox():
    # i70 residue: noo-cli renders `_INBOX_gw.<name>.>` for each add-on
    # principal; the gateway addresses that add-on's subjects to the same.
    gw_inbox = _const(GRANTS, "GATEWAY_INBOX")
    assert gw_inbox == _const(GW_CREDS, "INBOX_PREFIX")
    names = re.findall(r'AddonPrincipal \{\s*name: "([a-z_]+)"', GRANTS.read_text())
    assert names == ["trellion", "trellion_intel"], names
    for name in names:
        const = f"{name.upper()}_REPLY_PREFIX"
        assert _const(GW_CREDS, const) == f"{gw_inbox}.{name}", (
            f"{name} may publish replies on {gw_inbox}.{name}.> but the gateway's {const} differs"
        )
    assert "fn addon_reply_inbox" in GRANTS.read_text()
    assert 'format!("{GATEWAY_INBOX}.{name}.>")' in GRANTS.read_text()


def test_the_gateway_uses_the_scoped_inboxes():
    # The constants are only half of it: the requests must be the ones using them.
    wc = (GW / "worker_client.rs").read_text()
    assert wc.count("reply_prefix_for(subject)") >= 2, "request_with_timeout and request_stream"
    assert "WORKER_REPLY_PREFIX" not in wc, "an add-on subject must not be addressed to the worker's prefix"
    creds = GW_CREDS.read_text()
    assert "crate::addons::is_trellion_subject(subject)" in creds
    assert "crate::addons::is_trellion_intel_subject(subject)" in creds
    assert "nats.request(" not in wc and "nats.request_with_headers(" not in wc, (
        "a worker request on the gateway's default inbox loses its reply across a reload"
    )
    dispatch = (GW / "coordinator/dispatch.rs").read_text()
    assert "node_reply_prefix(node)" in dispatch
    assert "send_request(harness_run_subject(&node), node_request(" in dispatch
    assert "send_request(task_subject(&node), crate::coordinator::node_request(" in (GW / "tasks.rs").read_text()


def test_the_worker_grant_renders_it_in_publish():
    allow = _publish_allow(_role_block("Worker"))
    assert '\\"{WORKER_REPLY_INBOX}\\"' in allow, f"worker publish allow is [{allow}]"


def test_the_node_grant_renders_its_own_prefix_in_publish():
    allow = _publish_allow(_role_block("Node"))
    assert '\\"{NODE_REPLY_ROOT}.{tok}.>\\"' in allow, f"node publish allow is [{allow}]"


def test_no_principal_holds_another_ones_prefix():
    # Least privilege: the worker never answers a node's requests, a node
    # never answers the worker's or the gateway's shared inbox, and no one
    # holds the gateway's whole inbox.
    worker = _publish_allow(_role_block("Worker"))
    node = _publish_allow(_role_block("Node"))
    assert "NODE_REPLY_ROOT" not in worker and "_INBOX_gw.node" not in worker
    assert "WORKER_REPLY_INBOX" not in node and "_INBOX_gw.worker" not in node
    for allow in (worker, node):
        assert "_INBOX_gw.>" not in allow
    assert _const(GRANTS, "WORKER_REPLY_INBOX") != "_INBOX_gw.>"
