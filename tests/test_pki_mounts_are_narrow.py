# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No container mounts more of the PKI directory than its own identity.

an earlier change, generalised. `${NOO_PKI_DIR}` holds `ca.key`, the controller's
`gateway/gateway.key` and every `nodes/<id>/node.key`. Leaf keys were 0644
until 2026-09-28 (now 0600, or 0640 handed to the reading container's uid —
`KeyReader` in `noo-cli/src/pki.rs`); a service that mounts the directory
still holds every key its uid may read one `cat` away, whatever its config
names: a key that means "controller" or "any node". The first guard (test_monitoring_holds_no_gateway_key.py) looked
for the gateway key BY NAME and checked narrow mounts for three services, so
redis, nats, postgres, loki, the exporters, the stunnels, the inference
backends and noo-evolve all kept the whole directory.

The rule, for every service in every compose file and in the composed
projection:

* `ca.crt` — anyone.
* `services/<one name>` — one service leaf directory, whose name need not be
  the compose service's (stunnel-tei serves the `tei` leaf).
* `gateway/` — only the controller's own processes (CONTROLLER_SERVICES).
* `nodes/${NODE_ID…}` — only a node agent, and only its own id.
* `sso/grafana.pub` — Grafana alone, and only that one file: the PUBLIC half of the pair the gateway signs Grafana session tokens
  with. `sso/grafana.key` sits beside it and is the gateway's; mounting the
  `sso/` directory, or the key, or the pub into any other service, fails.
* `sso/`, `public/nodes`, `public/services` — the gateway alone. `public/` is the CLI-kept copy of every certificate under `nodes/`
  and `services/` and nothing else (`noo-cli/src/pki.rs`
  `sync_public_view`); the gateway reads certificate expiry there.

Nobody mounts the directory itself any more. The gateway did until an earlier change: as uid 65532 it could then read every key handed to 65532 — loki's,
prometheus's, alertmanager's, node-exporter's, llamacpp's — because a file
mode cannot tell two processes with one uid apart. So the last test here is
not about the shape of a mount but about what it exposes: over the PKI
layout the CLI writes, the gateway's mounts reach exactly two private keys,
`gateway/gateway.key` and `sso/grafana.key`, both its own.

Anything else — the root, `ca.key`, another node's dir, a second service leaf
— fails.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import full_projection, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))

# Who may mount the PKI root: nobody (the design retired the gateway's).
ROOT_HOLDERS: set[str] = set()
# The gateway's view: sso/ (the key it signs Grafana sessions with, beside
# the public half) and the certificate-only copies of nodes/ and services/.
GATEWAY_ONLY = {"sso", "public/nodes", "public/services"}
# Exactly what the gateway mounts, and the two private keys that reaches.
GATEWAY_PKI_MOUNTS = {"ca.crt", "gateway", "sso", "public/nodes", "public/services"}
GATEWAY_OWN_KEYS = {"gateway/gateway.key", "sso/grafana.key"}
# The controller's own processes: they present gateway/gateway.crt because
# they ARE the controller (see test_monitoring_holds_no_gateway_key.py).
# trellion, trellion-intel, worker and worker-extra present their own leaves
# since the gateway is the one process that IS the controller.
CONTROLLER_SERVICES = {"gateway"}
# Node agents present their own node leaf.
NODE_AGENT_SERVICES = {"node-agent", "node-agent-sensors"}
# The one non-certificate PKI file a non-gateway service may hold, and who:
# the public half of the Grafana SSO pair (the design A). Exactly this
# path — never `sso/` or `sso/grafana.key`.
SSO_PUBLIC_HOLDERS = {"sso/grafana.pub": {"grafana"}}

_PKI_ROOT = re.compile(r"^\$\{?NOO_PKI_DIR(?::?-[^}]*)?\}?(?P<rel>.*)$")
_SERVICE_LEAF = re.compile(r"^services/[A-Za-z0-9._-]+$")
_OWN_NODE_LEAF = re.compile(r"^nodes/\$\{NODE_ID(?::?-[^}/]*)?\}$")


def _source_of(vol) -> str:
    """The host side of a mount. Short syntax is split at the first colon
    OUTSIDE `${…}`: `${NOO_PKI_DIR:-./.pki-placeholder}:/tls:ro` has three."""
    if isinstance(vol, dict):
        return str(vol.get("source") or "")
    depth = 0
    for i, ch in enumerate(str(vol)):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ":" and depth == 0:
            return str(vol)[:i]
    return str(vol)


def violations(services: dict) -> tuple[list[str], int]:
    """(problems, number of PKI mounts seen) over a `services:` mapping."""
    problems: list[str] = []
    seen = 0
    for name, svc in sorted(services.items()):
        leaves: set[str] = set()
        for vol in (svc or {}).get("volumes") or []:
            src = _source_of(vol)
            if "ca.key" in src or "node.key" in src or "gateway.key" in src or "grafana.key" in src:
                problems.append(f"{name}: mounts a private key file directly: {src!r}")
                continue
            m = _PKI_ROOT.match(src)
            if not m:
                continue
            seen += 1
            rel = m.group("rel").strip("/")
            if rel == "":
                if name not in ROOT_HOLDERS:
                    problems.append(
                        f"{name}: mounts the whole PKI directory ({src!r}) — that is ca.key, "
                        "gateway.key and every node.key. Mount `…/ca.crt` and "
                        f"`…/services/<its leaf>` instead."
                    )
            elif rel == "ca.crt":
                pass
            elif _SERVICE_LEAF.match(rel):
                leaves.add(rel)
            elif rel == "gateway":
                if name not in CONTROLLER_SERVICES:
                    problems.append(
                        f"{name}: mounts gateway/ — the controller's identity, which a node agent "
                        "reads as 'this caller may command me'"
                    )
            elif _OWN_NODE_LEAF.match(rel):
                if name not in NODE_AGENT_SERVICES:
                    problems.append(f"{name}: mounts a node leaf ({rel}) and is not a node agent")
            elif rel in GATEWAY_ONLY:
                if name != "gateway":
                    problems.append(
                        f"{name}: mounts {rel!r}, which only the gateway holds (an earlier change: "
                        "sso/ carries its signing key; public/ is its certificate view)"
                    )
            elif rel in SSO_PUBLIC_HOLDERS:
                if name not in SSO_PUBLIC_HOLDERS[rel]:
                    problems.append(
                        f"{name}: mounts {rel!r}, which only {sorted(SSO_PUBLIC_HOLDERS[rel])} verify "
                        "tokens with"
                    )
            else:
                problems.append(
                    f"{name}: mounts {rel!r} from the PKI dir; allowed are ca.crt and "
                    "services/<one leaf> (gateway/ for the controller, nodes/${NODE_ID} "
                    "for a node agent)"
                )
        if len(leaves) > 1:
            problems.append(f"{name}: mounts more than one service leaf: {sorted(leaves)}")
    return problems, seen


def pki_mounts_of(svc: dict) -> list[str]:
    """The PKI-relative sources a service mounts (`""` = the root)."""
    out = []
    for vol in (svc or {}).get("volumes") or []:
        m = _PKI_ROOT.match(_source_of(vol))
        if m:
            out.append(m.group("rel").strip("/"))
    return out


# The private keys the CLI writes under the PKI dir (`noo-cli/src/pki.rs`,
# its module docs and `SERVICE_KEY_READERS`), with a representative node and
# door. `public/` holds none: `sync_public_view` copies `*.crt` only and
# removes anything else (`public_view_tests` in pki.rs plant a key there).
def pki_key_layout() -> set[str]:
    src = (ROOT / "noo-cli" / "src" / "pki.rs").read_text()
    table = src.split("pub const SERVICE_KEY_READERS", 1)[1].split("];", 1)[0]
    services = set(re.findall(r'\("([a-z0-9-]+)",\s*KeyReader::', table))
    assert {"loki", "prometheus", "alertmanager", "node-exporter", "llamacpp"} <= services, services
    keys = {"ca.key", "signing.key", "gateway/gateway.key", "sso/grafana.key"}
    keys |= {f"services/{s}/service.key" for s in services}
    keys |= {"nodes/host9/node.key", "nodes/host9/services/vllm/service.key"}
    return keys


def keys_reached(mounts: list[str], keys: set[str]) -> set[str]:
    """Which keys a set of PKI-relative mounts exposes. `public/…` holds
    certificates only, so it reaches no key whatever its name."""
    reached = set()
    for rel in mounts:
        if rel.startswith("public/") or rel == "public":
            continue
        for k in keys:
            if rel == "" or k == rel or k.startswith(rel + "/"):
                reached.add(k)
    return reached


def test_the_composed_stack_mounts_pki_narrowly():
    services = full_projection()["services"]
    problems, seen = violations(services)
    # Not vacuous: the stack mounts PKI material in well over a dozen places.
    assert seen >= 20, f"only {seen} PKI mounts found — did the mount syntax change?"
    assert not problems, "\n".join(problems)


def test_the_gateway_reaches_only_its_own_keys():
    """an earlier change, statically: the gateway's PKI mounts, over the key
    layout the CLI writes, reach exactly `gateway/gateway.key` and
    `sso/grafana.key`. The pre-1239 root mount reached every key in the
    tree; mounting `services/loki` would reach loki's."""
    keys = pki_key_layout()
    for services in (full_projection()["services"], untag(load_raw(ROOT / "docker-compose.cluster.yml"))["services"]):
        gw = pki_mounts_of(services["gateway"])
        assert set(gw) == GATEWAY_PKI_MOUNTS, f"the gateway's PKI mounts changed: {sorted(gw)}"
        assert keys_reached(gw, keys) == GATEWAY_OWN_KEYS, sorted(keys_reached(gw, keys))
    # The rule itself, planted: the old root mount and one extra leaf.
    assert keys_reached([""], keys) == keys
    assert "services/loki/service.key" in keys_reached(sorted(GATEWAY_PKI_MOUNTS) + ["services/loki"], keys)


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_compose_file_mounts_pki_narrowly(path):
    # Every file as written too: dist and gpu-embed are not in the add-on
    # projection, and a site copy of an overlay is read on its own.
    services = untag(load_raw(path)).get("services") or {}
    problems, _ = violations(services)
    assert not problems, f"{path.name}:\n" + "\n".join(problems)


def test_the_checker_catches_a_wide_mount():
    # The rule itself, planted: each of these must be refused.
    bad = {
        "loki": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}:/tls:ro"]},
        "redis": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/:/tls:ro"]},
        "nats": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/ca.key:/tls/ca.key:ro"]},
        "grafana": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/gateway:/app/pki/gateway:ro"]},
        "postgres": {"volumes": ["${NOO_PKI_DIR}/nodes:/tls/nodes:ro"]},
        # The SSO pair: the directory, the private half, and the public half
        # into a service that is not Grafana are each refused.
        "loki-sso": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/sso:/app/pki/sso:ro"]},
        "grafana-key": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/sso/grafana.key:/app/pki/sso/grafana.key:ro"]},
        "prometheus-pub": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/sso/grafana.pub:/app/pki/sso/grafana.pub:ro"]},
        "node-agent": {"volumes": ["${NOO_PKI_DIR}/nodes/host9:/app/pki/nodes/host9:ro"]},
        # the root is nobody's now, the gateway's included;
        # its certificate view is its alone.
        "gateway": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}:/app/pki:ro"]},
        "worker": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/public/nodes:/app/pki/nodes:ro"]},
        "vllm": {"volumes": [
            "${NOO_PKI_DIR}/services/vllm:/app/pki/services/vllm:ro",
            "${NOO_PKI_DIR}/services/postgres:/app/pki/services/postgres:ro",
        ]},
    }
    problems, _ = violations(bad)
    assert {p.split(":")[0] for p in problems} == set(bad), problems
    # And the one allowed shape is allowed — otherwise the projection test
    # above would be the only thing saying so.
    good = {"grafana": {"volumes": ["${NOO_PKI_DIR:-./.pki-placeholder}/sso/grafana.pub:/app/pki/sso/grafana.pub:ro"]}}
    assert violations(good) == ([], 1)
    gw = {"gateway": {"volumes": [f"${{NOO_PKI_DIR:-./.pki-placeholder}}/{r}:/app/pki/x:ro" for r in sorted(GATEWAY_PKI_MOUNTS)]}}
    assert violations(gw) == ([], len(GATEWAY_PKI_MOUNTS))
