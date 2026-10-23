# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A stunnel door accepts the cluster CA's leaves only for the callers it has.

`verify = 2` alone accepts ANY certificate the cluster CA issued: a node's,
grafana's, a backend's. Every door therefore pins the peer by the DNS name in
its leaf's SANs (`checkHost`, any one match accepts), mirroring what the
model-cache nginx door does with O=.

Two kinds of door:

* tei, tei-gpu, reranker: only containers call them; the pins are static.
* ollama, ollama-embed, ollama-embed-cpu, llamacpp (i132): the same static
  pins for the service leaves, PLUS the controller's own HOST node-agent,
  which dials them with its node leaf. stunnel cannot match O=, and a node
  leaf's distinguishing SAN is its node id, which a static conf cannot list;
  compose's `stunnel-self-pin` entrypoint appends `checkHost = $NODE_ID` at
  start and refuses (exit 78) to start without one, so the door never falls
  back to "any cluster-CA leaf". The pin must also never be a name every leaf
  carries (`localhost`, `noo-controller`).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCK = ROOT / "docker"

STATIC_ONLY = {"tei", "tei-gpu", "reranker"}
SELF_PINNED = {"ollama", "ollama-embed", "ollama-embed-cpu", "llamacpp"}
# The leaves that dial the doors (SAN names, from noo-cli/src/pki.rs).
CALLERS = {"gateway", "worker", "trellion", "trellion-intel", "evolve"}
# Names every cluster leaf carries; pinning on one would pin nothing.
EVERY_LEAF = {"localhost", "127.0.0.1", "noo-controller"}
# A door's own leaf may also be named so its healthcheck, which dials the
# door from inside with that leaf, passes.
OWN_LEAF_OK = {"ollama-embed", "ollama-embed-cpu"}
COMPOSE = ROOT / "docker-compose.cluster.yml"


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
    assert set(_all()) == STATIC_ONLY | SELF_PINNED, (
        "a new docker/stunnel-*.conf must be added to STATIC_ONLY or SELF_PINNED"
    )


@pytest.mark.parametrize("name", sorted(STATIC_ONLY | SELF_PINNED))
def test_every_door_requires_a_client_certificate(name):
    d = dict(_directives(_all()[name]))
    assert d.get("verify") == "2", f"{name}: verify is {d.get('verify')!r}"


@pytest.mark.parametrize("name", sorted(STATIC_ONLY))
def test_static_doors_name_their_callers(name):
    hosts = {v for k, v in _directives(_all()[name]) if k == "checkHost"}
    assert hosts == CALLERS, f"{name}: checkHost set is {sorted(hosts)}, want {sorted(CALLERS)}"
    assert not (hosts & EVERY_LEAF), f"{name} pins on a name every leaf carries"


@pytest.mark.parametrize("name", sorted(SELF_PINNED))
def test_self_pinned_doors_name_their_service_callers_statically(name):
    hosts = {v for k, v in _directives(_all()[name]) if k == "checkHost"}
    want = CALLERS | ({name} if name in OWN_LEAF_OK else set())
    assert hosts == want, f"{name}: checkHost set is {sorted(hosts)}, want {sorted(want)}"
    assert not (hosts & EVERY_LEAF), f"{name} pins on a name every leaf carries"


def _services() -> dict:
    return yaml.safe_load(COMPOSE.read_text())["services"]


@pytest.mark.parametrize("name", sorted(SELF_PINNED))
def test_self_pinned_doors_append_the_controllers_node_id_at_start(name):
    """The host agent's node leaf is the one caller a static conf cannot name:
    compose renders it from NODE_ID at start, fail-closed."""
    svc = _services()[f"stunnel-{name}"]
    ep = svc.get("entrypoint")
    assert isinstance(ep, list) and ep[:2] == ["sh", "-c"], f"stunnel-{name}: no self-pin entrypoint ({ep!r})"
    script = ep[2]
    assert "checkHost = %s" in script and "/tmp/stunnel.conf" in script, script
    assert "exit 78" in script, "an unset NODE_ID must refuse to start, not start unpinned"
    assert 'case "$$id" in' in script and '""|auto|' in script, "an empty or `auto` id must be refused"
    assert "exec stunnel /tmp/stunnel.conf" in script
    env = svc.get("environment") or []
    assert "NOO_STUNNEL_SELF_NODE=${NODE_ID:-}" in env, f"stunnel-{name} does not hand the door NODE_ID: {env!r}"


def _run_self_pin(tmp_path, node_id):
    """Run the compose entrypoint script for real, with `stunnel` replaced by a
    stub that prints the conf it was handed, and the two paths redirected."""
    script = _services()["stunnel-ollama"]["entrypoint"][2].replace("$$", "$")
    conf = tmp_path / "in.conf"
    conf.write_text("[ollama]\nverify = 2\n")
    out = tmp_path / "out.conf"
    script = script.replace("/etc/stunnel/stunnel.conf", str(conf)).replace("/tmp/stunnel.conf", str(out))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "stunnel"
    stub.write_text('#!/bin/sh\ncat "$1"\n')
    stub.chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "NOO_STUNNEL_SELF_NODE": node_id}
    return subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, cwd=tmp_path)


def test_the_self_pin_entrypoint_appends_the_node_id_to_the_conf(tmp_path):
    r = _run_self_pin(tmp_path, "host8")
    assert r.returncode == 0, r.stderr
    lines = r.stdout.splitlines()
    assert lines[:2] == ["[ollama]", "verify = 2"] and lines[-1] == "checkHost = host8", r.stdout


@pytest.mark.parametrize("bad", ["", "auto", "a b", "x;rm -rf /", "$(id)", "../x\ny", "host8\ncheckHost = evil"])
def test_the_self_pin_entrypoint_refuses_an_unusable_node_id(tmp_path, bad):
    """Fail closed: no unpinned start, and no way to smuggle a second directive."""
    r = _run_self_pin(tmp_path, bad)
    assert r.returncode == 78, (r.returncode, r.stdout, r.stderr)
    assert "NODE_ID" in r.stderr and "noo stack restart --force" in r.stderr, "the refusal names the fix"
    assert r.stdout == "", "stunnel must not have run"


@pytest.mark.parametrize("name", sorted(STATIC_ONLY))
def test_static_doors_have_no_self_pin_entrypoint(name):
    """tei/reranker have no host-agent caller: they must not start refusing
    on a missing NODE_ID."""
    assert "entrypoint" not in _services()[f"stunnel-{name}"]


def test_pinned_callers_exist_as_leaf_names():
    """Each pinned name is a service leaf (or the gateway's) the PKI issues, so
    the pin cannot be a typo that refuses everyone."""
    pki = (ROOT / "noo-cli/src/pki.rs").read_text()
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert '"gateway".into()' in pki, "the gateway leaf lost its `gateway` SAN"
    svc_list = re.search(r"pub\(crate\) const SVC_LIST: &\[&str\] = &\[(.*?)\];", steps, re.S).group(1)
    for n in CALLERS - {"gateway"}:
        assert f'"{n}"' in svc_list, f"{n} is not in SVC_LIST: no service leaf is issued for it"
