# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Which compose services may hold the Docker API — by name, and today: none.

Fleet logging phase 4 (2026-09-28). `/var/run/docker.sock` is host root:
`POST /containers/create` with `Binds: ["/:/host"]` and the privileged flag
is the whole exploit, and a `:ro` mount flag does not change the API. So
every socket mount in the stack is a decision, and this guard is where the
decision is written down.

History, so the empty set below reads as deliberate: an earlier change took the
socket off the gateway (host-watcher + spool, `GATEWAY_DOCKER_CONTAINMENT.md`)
and off the compose node-agent (its profile became opt-in), and fronted
promtail's read-only discovery with `docker-socket-proxy` — the sole
remaining holder. Phase 4 retired promtail and the proxy: the controller's
container logs ship through the node-agent that runs on the controller
HOST (a systemd unit in the `docker` group, never a container), so nothing
in any compose file mounts the socket or dials a socket proxy any more.

The compose `node-agent` service (`--profile node-agent-compose`) is the
one place a site may re-add the mount, deliberately, in its own copy; the
shipped file does not, and this guard keeps the shipped file that way.
`ALLOWED_SOCKET_HOLDERS` is empty on purpose — adding a name here is the
review.

Planted: a `/var/run/docker.sock` volume on the gateway → the first test
names it; a `DOCKER_HOST=tcp://…` env on any service → the second.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import full_projection, load_raw, untag

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = sorted(ROOT.glob("docker-compose*.yml"))

# Services that may mount the Docker socket. Empty, and meant to be.
ALLOWED_SOCKET_HOLDERS: set[str] = set()
# Services that never may, whatever the set above says — the ones whose
# compromise is the threat model (the gateway is the LAN-facing process).
NEVER = {"gateway", "worker", "worker-extra", "trellion", "trellion-intel", "grafana", "loki", "prometheus"}

_SOCKET = re.compile(r"docker\.sock")
_PROXY_DIAL = re.compile(r"^(DOCKER_HOST|DOCKER_SD_HOST)=|tcp://[^\s]*:2375|docker-socket-proxy", re.M)


def _mount_sources(svc: dict) -> list[str]:
    out = []
    for v in (svc or {}).get("volumes") or []:
        out.append(str(v.get("source") or "") if isinstance(v, dict) else str(v))
    return out


def _env_lines(svc: dict) -> list[str]:
    env = (svc or {}).get("environment") or []
    if isinstance(env, dict):
        return [f"{k}={v}" for k, v in env.items()]
    return [str(e) for e in env]


def socket_holders(services: dict) -> dict[str, list[str]]:
    """service → the mount sources that name docker.sock."""
    out = {}
    for name, svc in sorted(services.items()):
        hits = [s for s in _mount_sources(svc) if _SOCKET.search(s)]
        if hits:
            out[name] = hits
    return out


def proxy_dialers(services: dict) -> dict[str, list[str]]:
    """service → env/command lines that point at a Docker API over TCP."""
    out = {}
    for name, svc in sorted(services.items()):
        cmd = (svc or {}).get("command") or []
        cmd = [cmd] if isinstance(cmd, str) else [str(c) for c in cmd]
        hits = [line for line in _env_lines(svc) + cmd if _PROXY_DIAL.search(line)]
        if hits:
            out[name] = hits
    return out


def test_no_shipped_service_mounts_the_docker_socket():
    services = full_projection()["services"]
    assert len(services) > 20, "the compose parse found almost nothing — vacuous"
    holders = socket_holders(services)
    rogue = {n: h for n, h in holders.items() if n not in ALLOWED_SOCKET_HOLDERS}
    assert not rogue, (
        f"{rogue} mount the Docker socket. That is host root (POST /containers/create "
        "chooses binds and the privileged flag). The stack has held it in no container "
        "since fleet logging phase 4; name the service in ALLOWED_SOCKET_HOLDERS with the "
        "reason, or take the mount out."
    )
    assert not (set(holders) & NEVER)


def test_no_shipped_service_dials_a_docker_socket_proxy():
    services = full_projection()["services"]
    dialers = proxy_dialers(services)
    assert not dialers, (
        f"{dialers} point at a Docker API over TCP. docker-socket-proxy left with "
        "promtail (fleet logging phase 4); a read-only proxy only helps a client whose "
        "legitimate calls are all GETs, and no shipped service is one."
    )
    assert "docker-socket-proxy" not in services


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_every_compose_file_as_written(path):
    # dist and the overlays are not all in the projection; a site copy of an
    # overlay is read on its own.
    services = untag(load_raw(path)).get("services") or {}
    holders = {n: h for n, h in socket_holders(services).items() if n not in ALLOWED_SOCKET_HOLDERS}
    assert not holders, f"{path.name}: {holders}"
    assert not proxy_dialers(services), f"{path.name}: {proxy_dialers(services)}"


def test_the_checker_catches_the_plants():
    bad = {
        "gateway": {"volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]},
        "node-agent": {"volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]},
        "promtail": {"environment": ["DOCKER_SD_HOST=tcp://docker-socket-proxy:2375"]},
        "shipper": {"environment": {"DOCKER_HOST": "tcp://10.0.0.1:2375"}},
        "clean": {"volumes": ["./monitoring/loki:/etc/loki:ro"], "environment": ["NOO_LOKI_URL=https://loki:3100"]},
    }
    assert set(socket_holders(bad)) == {"gateway", "node-agent"}
    assert set(proxy_dialers(bad)) == {"promtail", "shipper"}


def test_the_allow_list_is_empty_on_purpose():
    # Someone adding a holder edits this too — the docstring's claim is a
    # pinned fact, not prose.
    assert ALLOWED_SOCKET_HOLDERS == set(), (
        "a service may hold the Docker socket now; rewrite the docstring and "
        "docs/security/node-agent.md with the reason"
    )
