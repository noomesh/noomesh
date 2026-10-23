# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every service presents its own leaf; only the gateway presents the gateway's.

an earlier change. `gateway/gateway.{crt,key}` carries ``O="Mesh Cluster
Gateway"``: it is the controller's identity, the one a node agent reads as
"this caller may command me". #573 narrowed who can READ it by
mount; the stack-v0.2.81 rehearsal found noo-trellion and noo-trellion-intel
still PRESENTING it — every DSN's ``sslcert``/``sslkey`` and ``NOO_TLS_*``
named it, through the shared ``x-trellion-env`` anchor that intel inherits by
``extends``. Each now presents ``services/<own name>`` mounted at
``/app/pki/leaf``.

The rule, over the composed projection and every compose file as written:

* No service but the gateway mounts ``gateway/`` or any file in it.
* No service but the gateway names ``gateway.key`` anywhere, or
  ``gateway.crt`` in an identity position (a DSN's ``sslcert``, a ``*_CERT``
  or ``*_KEY`` variable, a command). TRUSTING the gateway's certificate —
  ``sslrootcert``, a ``*_CA`` variable — is fine and not flagged.
* trellion and noo-worker (with worker-extra) each mount exactly
  one leaf, their own, and every certificate path they name resolves into it.

``KNOWN_HOLDERS`` is EMPTY and pinned empty (an earlier change closed). The
worker was the last holder: its only node-agent calls that needed the
controller's authority were heartbeat.py's ``/cleanup/*`` dry-run detectors,
which disk_cleanup never reached (the action is Rust-native in the gateway,
which holds the leaf) and which now refuse loudly instead of dialling.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import env_of, full_projection, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))

OWNER = "gateway"
# the design is closed: no service but the gateway holds its leaf.
# `test_the_exception_list_is_empty` fails on any addition.
KNOWN_HOLDERS: frozenset[str] = frozenset()

# service -> (its own leaf dir, the fewest Postgres DSNs it names)
OWN_LEAVES = {
    "trellion": ("services/trellion", 5),
    # trellion-intel: moved with the overlay to the add-on repo (N6)
    "worker": ("services/worker", 2),
    "worker-extra": ("services/worker", 2),
}
LEAF_TARGET = "/app/pki/leaf"

_PKI_SRC = re.compile(r"^\$\{?NOO_PKI_DIR(?::?-[^}]*)?\}?/?(?P<rel>.*)$")
# A gateway leaf file named as something presented, not something trusted.
_GW_FILE = re.compile(r"gateway\.(crt|key)\b")
_TRUST_PARAM = re.compile(r"sslrootcert=[^&\s'\"]*gateway\.crt")


def _source_target(vol) -> tuple[str, str]:
    if isinstance(vol, dict):
        return str(vol.get("source") or ""), str(vol.get("target") or "")
    s = re.sub(r":(ro|rw|z|Z)$", "", str(vol))
    depth, cut = 0, None
    for i, ch in enumerate(s):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ":" and depth == 0:
            cut = i
            break
    return (s, "") if cut is None else (s[:cut], s[cut + 1:])


def _identity_uses(name: str, svc: dict) -> list[str]:
    """Where `svc` holds or presents the gateway's leaf."""
    out = []
    for vol in svc.get("volumes") or []:
        src, _ = _source_target(vol)
        m = _PKI_SRC.match(src)
        rel = m.group("rel").strip("/") if m else ""
        if m and (rel == "gateway" or rel.startswith("gateway/")):
            out.append(f"{name}: mounts {src!r} — the controller's leaf")
        elif _GW_FILE.search(src):
            out.append(f"{name}: mounts {src!r}")
    for key, value in env_of(svc).items():
        value = str(value or "")
        if "gateway.key" in value:
            out.append(f"{name}: {key} names gateway.key")
            continue
        if not _GW_FILE.search(value):
            continue
        # Trust positions: the CA a client verifies against. Everything else
        # that names gateway.crt presents it.
        if key.endswith("_CA") or key.endswith("_CA_FILE"):
            continue
        if _GW_FILE.search(_TRUST_PARAM.sub("", value)):
            out.append(f"{name}: {key} presents gateway.crt")
    cmd = svc.get("command") or []
    blob = cmd if isinstance(cmd, str) else "\n".join(map(str, cmd))
    if _GW_FILE.search(blob):
        out.append(f"{name}: its command names the gateway leaf")
    return out


def holders(services: dict) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for name, svc in sorted(services.items()):
        uses = _identity_uses(name, svc or {})
        if uses:
            found[name] = uses
    return found


def _problems(services: dict) -> list[str]:
    return [u for n, uses in holders(services).items() if n != OWNER and n not in KNOWN_HOLDERS for u in uses]


def test_no_service_but_the_gateway_presents_the_gateway_leaf():
    services = full_projection()["services"]
    found = holders(services)
    # Not vacuous: the gateway itself must still be seen holding its own leaf.
    assert OWNER in found, "the gateway no longer names its own leaf — the checker is not looking"
    assert _problems(services) == [], "\n".join(_problems(services))


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_compose_file_as_written(path):
    # A site copy of an overlay is read on its own, and a value in an `x-`
    # anchor reaches every service that merges it.
    raw = untag(load_raw(path))
    services = dict(raw.get("services") or {})
    for key, block in raw.items():
        if key.startswith("x-") and isinstance(block, dict) and key != "x-noo-addon":
            services[f"<{key}>"] = {"environment": block}
    assert _problems(services) == [], f"{path.name}:\n" + "\n".join(_problems(services))


def test_each_service_presents_exactly_its_own_leaf():
    services = full_projection()["services"]
    for name, (leaf, min_dsns) in OWN_LEAVES.items():
        svc = services[name]
        pki = {}
        for vol in svc.get("volumes") or []:
            src, tgt = _source_target(vol)
            m = _PKI_SRC.match(src)
            if m:
                pki[m.group("rel").strip("/")] = tgt
        assert pki == {"ca.crt": "/app/pki/ca.crt", leaf: LEAF_TARGET}, f"{name}: {pki}"
        env = env_of(svc)
        assert env["NOO_TLS_CERT"].endswith(f"{LEAF_TARGET}/service.crt}}"), env["NOO_TLS_CERT"]
        assert env["NOO_TLS_KEY"].endswith(f"{LEAF_TARGET}/service.key}}"), env["NOO_TLS_KEY"]
        dsns = [v for v in env.values() if re.match(r"postgres(ql)?://", v or "")]
        assert len(dsns) >= min_dsns, f"{name}: only {len(dsns)} DSNs"
        for dsn in dsns:
            # Inside the leaf the DSN's certificate is the one issued for the
            # DSN's ROLE (`<leaf>/pg/<role>.crt`, CN = role: pg_hba requires
            # it, i132); the service's own `service.crt` is for the doors.
            role = re.match(r"postgres(?:ql)?://([^:@/]+)", dsn).group(1)
            assert f"sslcert={LEAF_TARGET}/pg/{role}.crt" in dsn and f"sslkey={LEAF_TARGET}/pg/{role}.key" in dsn, dsn


def test_the_exception_list_is_empty():
    assert KNOWN_HOLDERS == frozenset(), "an earlier change is closed: nothing but the gateway holds its leaf"
    found = set(holders(full_projection()["services"]))
    assert found == {OWNER}, (
        f"holders of the gateway leaf are now {sorted(found)}; only the gateway "
        "may present it. Give the service a services/<name> "
        "leaf instead."
    )


def test_the_checker_bites():
    """Planted: each shape is refused; trusting the gateway's cert is not."""
    gw = "${NOO_PKI_DIR:-./.pki-placeholder}"
    bad = {
        "dir": {"volumes": [f"{gw}/gateway:/app/pki/gateway:ro"]},
        "file": {"volumes": [f"{gw}/gateway/gateway.key:/k:ro"]},
        "long-form": {"volumes": [{"type": "bind", "source": "/home/u/.noo/pki/gateway/gateway.crt", "target": "/c"}]},
        "tls-key": {"environment": {"NOO_TLS_KEY": "/app/pki/gateway/gateway.key"}},
        "tls-cert": {"environment": {"NOO_TLS_CERT": "/app/pki/gateway/gateway.crt"}},
        "dsn": {"environment": {"DATABASE_URL": "postgresql://u@postgres/db?sslrootcert=/a/ca.crt&sslcert=/app/pki/gateway/gateway.crt&sslkey=/x/k"}},
        "cmd": {"command": ["sh", "-c", "cp /app/pki/gateway/gateway.key /tmp/k"]},
    }
    found = holders(bad)
    assert set(found) == set(bad), sorted(set(bad) - set(found))
    ok = {
        "trusts": {"environment": {
            "NOO_TLS_CA": "/app/pki/gateway/gateway.crt",
            "PEER_URL": "postgresql://u@h/db?sslrootcert=/app/pki/gateway/gateway.crt&sslcert=/app/pki/leaf/service.crt",
        }},
        "own": {"volumes": [f"{gw}/services/trellion:/app/pki/leaf:ro"],
                "environment": {"NOO_TLS_CERT": "/app/pki/leaf/service.crt"}},
    }
    assert holders(ok) == {}, holders(ok)
