# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A Python -> gateway self-call presents a credential from ONE place.

noomesh an earlier change. A per-consumer key is only worth having if every
internal caller actually presents it. The moment a second call site mints its
own bearer, that site keeps using the shared secret — and the install reads as
migrated while one consumer is not. That is not hypothetical: before this
guard, `channels/gateway_client.py` minted its own cluster token, and it read
only NOO_CLUSTER_SECRET, so on a controller carrying NOO_CONTROLLER_SECRET
alone it sent no header and every channel call 401'd silently.

The door is `cluster_auth.internal_gateway_headers`. It presents this
container's own NOO_GATEWAY_KEY and nothing else: the shared-HMAC fallback is
retired, as trellion's gateway_auth.py retired its own
.

NOT covered, deliberately: calls going the OTHER way, to a node agent. The
Python signers of those (`gateway/helpers.py::_node_agent_headers`,
`skill_executor.py`, `browser_tool.py`'s agent calls) are gone: node agents admit the controller's certificate, and
`tests/test_no_static_node_agent_token_sender.py` keeps the static token off
every agent call.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "noomesh"
DOOR = SRC / "cluster" / "cluster_auth.py"
# The other direction (gateway -> node), and the operator's CLI, are not
# self-calls. Each is named here with its reason so the exemption is a
# decision rather than a hole.
EXEMPT = {
    SRC / "cli_utils.py": "the operator's CLI, not an internal service",
    # Not a gateway call: it signs calls INTO the browser container, which
    # requires the cluster HMAC on every route. A
    # per-consumer gateway key would be the wrong credential. (Its node-agent
    # calls are gone, )
    SRC / "tools" / "browser_tool.py": "calls into the browser container (an earlier change R35)",
}


def _self_call_signers() -> list[tuple[Path, int]]:
    """Call sites that mint a cluster token outside the door."""
    hits: list[tuple[Path, int]] = []
    for path in sorted(SRC.rglob("*.py")):
        if path == DOOR or path in EXEMPT:
            continue
        # utf-8-sig: several modules in this tree still carry a BOM from the
        # Windows era. Python imports them fine (source is read as utf-8-sig),
        # but a naive read_text() leaves U+FEFF and ast.parse refuses it — the
        # guard would then fail for an unrelated reason on the first file.
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
                if name == "create_cluster_token":
                    hits.append((path, node.lineno))
    return hits


def test_only_the_door_mints_a_self_call_bearer() -> None:
    hits = _self_call_signers()
    assert not hits, (
        "these mint a cluster token directly instead of calling "
        "cluster_auth.internal_gateway_headers():\n"
        + "\n".join(f"  {p.relative_to(SRC.parent.parent)}:{n}" for p, n in hits)
        + "\nA second signer keeps presenting the shared secret after the door starts "
        "preferring a per-consumer key — the install then reads as migrated while that "
        "caller is not. Add it to EXEMPT only with a reason, as the entries there have."
    )


def test_the_exemptions_still_exist() -> None:
    """An exemption naming a file that has moved is an exemption for nothing,
    and would hide a real signer appearing under the old name."""
    for path, why in EXEMPT.items():
        assert path.exists(), f"exempt file is gone: {path} ({why})"


def test_the_door_presents_the_per_consumer_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from noomesh.cluster import cluster_auth

    monkeypatch.setenv("NOO_GATEWAY_KEY", "noo-sk-its-own")
    monkeypatch.setenv("NOO_CONTROLLER_SECRET", "shared-hmac")
    assert cluster_auth.internal_gateway_headers("worker") == {
        "Authorization": "Bearer noo-sk-its-own"
    }, "a container holding its own key must present THAT, not the shared secret"


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_no_key_sends_no_shared_secret(monkeypatch: pytest.MonkeyPatch, blank) -> None:
    """an earlier change, the retirement. Absent or blank key → NO header, even
    with both shared secrets in the environment. Before the retirement this
    minted `<actor>:<ts>:<hmac>` under NOO_CONTROLLER_SECRET; the gateway now
    refuses that from every actor, so the fallback could only turn "no key"
    into an anonymous 403."""
    from noomesh.cluster import cluster_auth

    if blank is None:
        monkeypatch.delenv("NOO_GATEWAY_KEY", raising=False)
    else:
        monkeypatch.setenv("NOO_GATEWAY_KEY", blank)
    monkeypatch.setenv("NOO_CONTROLLER_SECRET", "controller-secret")
    monkeypatch.setenv("NOO_CLUSTER_SECRET", "fleet-secret")
    monkeypatch.setattr(cluster_auth, "CLUSTER_SECRET", "fleet-secret")
    assert cluster_auth.internal_gateway_headers("worker") == {}


def test_the_door_reads_no_controller_secret() -> None:
    """The module no longer reads NOO_CONTROLLER_SECRET at all, so no Python
    process can sign with it by accident."""

    tree = ast.parse(DOOR.read_text(encoding="utf-8-sig"))
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not any(s == "NOO_CONTROLLER_SECRET" for s in strings), "cluster_auth reads the controller secret again"
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "CONTROLLER_SECRET" not in names and "_self_call_secret" not in names

def test_no_python_module_reads_the_controller_secret_for_a_self_call() -> None:
    """Across the package, only the bus-principal verifier may still name it
    (an earlier change moves that separately)."""
    allowed = {SRC / "secret_env.py", SRC / "secrets.py", SRC / "gateway" / "bus_principal.py"}
    hits = []
    for path in sorted(SRC.rglob("*.py")):
        if path in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value == "NOO_CONTROLLER_SECRET":
                hits.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not hits, f"reads NOO_CONTROLLER_SECRET: {hits}"


def test_create_cluster_token_has_no_default_key() -> None:
    """Review L6: no caller can sign with a shared secret by omission — the
    key is a required argument, and an empty one is refused."""
    from noomesh.cluster import cluster_auth

    with pytest.raises(TypeError):
        cluster_auth.create_cluster_token("gateway")  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        cluster_auth.create_cluster_token("gateway", "")
    assert cluster_auth.create_cluster_token("gateway", "s").startswith("gateway:")
