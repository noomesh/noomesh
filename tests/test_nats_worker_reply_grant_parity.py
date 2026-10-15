# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The worker's static reply grant IS the gateway's inbox, and only the worker's (i69).

`allow_responses` entries live in a per-connection map that nats-server
replaces on every config reload, so a worker reply to a request delivered
before a SIGHUP was refused (`Publish Violation` on `_INBOX_gw.…`). The fix
grants the worker a static publish on the gateway's reply inbox. Two crates,
no shared source: `noo-cli` renders the grant, `gateway-rust` picks the
inbox prefix. If either moves alone the worker's replies are refused again —
silently, because NATS reports a refused publish asynchronously.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GRANTS = ROOT / "noo-cli/src/commands/nats_users.rs"
GW_CREDS = ROOT / "gateway-rust/src/nats_credentials.rs"
GW_STATE = ROOT / "gateway-rust/src/state.rs"


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


def test_the_worker_reply_grant_is_the_gateway_inbox():
    prefix = _const(GW_CREDS, "INBOX_PREFIX")
    grant = _const(GRANTS, "GATEWAY_REPLY_INBOX")
    assert grant == f"{prefix}.>", (
        f"the worker may publish replies on {grant!r} but the gateway's inbox is {prefix!r}.*: "
        "every worker reply that straddles a NATS reload is refused"
    )


def test_the_gateway_connects_with_that_prefix():
    # The constant is only half of it: the bus connection must be the one using it.
    assert "crate::nats_credentials::INBOX_PREFIX" in GW_STATE.read_text()


def test_the_worker_grant_renders_it_in_publish():
    allow = _publish_allow(_role_block("Worker"))
    assert '\\"{GATEWAY_REPLY_INBOX}\\"' in allow, f"worker publish allow is [{allow}]"


def test_no_other_principal_holds_it():
    # Least privilege: nodes answer only through allow_responses.
    node = _role_block("Node")
    assert "GATEWAY_REPLY_INBOX" not in node and "_INBOX_gw" not in node
