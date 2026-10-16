# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A stunnel door accepts the cluster CA's leaves only for the callers it has.

`verify = 2` alone accepts ANY certificate the cluster CA issued: a node's,
grafana's, a backend's. The doors whose callers are all containers pin the
peer by the DNS name in its leaf's SANs (`checkHost`, any one match accepts),
mirroring what the model-cache nginx door does with O=.

The sibling doors that the controller's own HOST node-agent also dials with
its node leaf (ollama, ollama-embed, ollama-embed-cpu, llamacpp) are NOT
pinned: stunnel cannot match O=, and a node leaf's SAN is its own name, which
a static conf cannot list. They are listed here as the known exception so a
change to either list is a reviewed edit, and every door keeps `verify = 2`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCK = ROOT / "docker"

PINNED = {"tei", "tei-gpu", "reranker"}
UNPINNED_NODE_AGENT_CALLERS = {"ollama", "ollama-embed", "ollama-embed-cpu", "llamacpp"}
# The leaves that dial the pinned doors (SAN names, from noo-cli/src/pki.rs).
CALLERS = {"gateway", "worker", "trellion", "trellion-intel", "evolve"}
# Names every cluster leaf carries; pinning on one would pin nothing.
EVERY_LEAF = {"localhost", "127.0.0.1", "noo-controller"}


def _directives(path: Path) -> list[tuple[str, str]]:
    out = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        k, _, v = line.partition("=")
        out.append((k.strip(), v.strip()))
    return out


def _all() -> dict[str, Path]:
    return {p.stem.removeprefix("stunnel-"): p for p in sorted(DOCK.glob("stunnel-*.conf"))}


def test_every_door_is_classified():
    assert set(_all()) == PINNED | UNPINNED_NODE_AGENT_CALLERS, (
        "a new docker/stunnel-*.conf must be added to PINNED or to the documented exception list"
    )


@pytest.mark.parametrize("name", sorted(PINNED | UNPINNED_NODE_AGENT_CALLERS))
def test_every_door_requires_a_client_certificate(name):
    d = dict(_directives(_all()[name]))
    assert d.get("verify") == "2", f"{name}: verify is {d.get('verify')!r}"


@pytest.mark.parametrize("name", sorted(PINNED))
def test_pinned_doors_name_their_callers(name):
    hosts = {v for k, v in _directives(_all()[name]) if k == "checkHost"}
    assert hosts == CALLERS, f"{name}: checkHost set is {sorted(hosts)}, want {sorted(CALLERS)}"
    assert not (hosts & EVERY_LEAF), f"{name} pins on a name every leaf carries"


@pytest.mark.parametrize("name", sorted(UNPINNED_NODE_AGENT_CALLERS))
def test_doors_the_host_agent_dials_are_not_pinned_by_accident(name):
    """A checkHost here would refuse the controller's own node-agent (node
    leaf, SAN = its node name). Make that a deliberate edit of this file."""
    assert not [v for k, v in _directives(_all()[name]) if k == "checkHost"]


def test_pinned_callers_exist_as_leaf_names():
    """Each pinned name is a service leaf (or the gateway's) the PKI issues, so
    the pin cannot be a typo that refuses everyone."""
    pki = (ROOT / "noo-cli/src/pki.rs").read_text()
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert '"gateway".into()' in pki, "the gateway leaf lost its `gateway` SAN"
    svc_list = re.search(r"pub\(crate\) const SVC_LIST: &\[&str\] = &\[(.*?)\];", steps, re.S).group(1)
    for n in CALLERS - {"gateway"}:
        assert f'"{n}"' in svc_list, f"{n} is not in SVC_LIST: no service leaf is issued for it"
