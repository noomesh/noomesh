# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No compose service bind-mounts a whole host tree.

Until 2026-09-11 the gateway and trellion carried
`/mnt:/host-fs/mnt:ro`, `/home:/host-fs/home:ro` and `/media:/host-fs/media:ro`
— "for the directory picker in the dashboard". That is the entire machine,
read-only, inside a network service: `~/.config/sops/age/keys.txt` (the key to
every other secret), `~/.ssh`, and every 0644 file in every home directory.
`USER nonroot` was the only wall, and on WSL `/mnt/*` is drvfs, which ignores
Unix permissions entirely — so there was no wall. Any file-read bug in the
gateway (R10 was one) read them all. Tracker row R22.

Host directories now enter a container ONE AT A TIME, through the
`docker-compose.override.yml` that `noo onboard` generates from the operator's
declared user dirs. This test is the thing that stops the wide mount coming
back the next time the picker is inconvenient.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
# trellion-intel / evolve overlays: moved with the overlay to the add-on repo (N6).
COMPOSE_FILES = ["docker-compose.cluster.yml", "docker-compose.dist.yml", "docker-compose.trellion.yml", "docker-compose.voice.yml", "docker-compose.gpu-embed.yml"]

# Sources no service may mount, at any mode, under any target. `/` is here
# because "read-only" is not a defence against READING, which is the whole
# threat.
FORBIDDEN = {"/", "/home", "/mnt", "/media", "/root", "/etc", "/usr", "/var", "/srv", "/opt", "/Users", "/run/media"}

# The one declared exception, named rather than filtered out quietly.
#
# node-exporter is the Prometheus host-metrics exporter: it mounts `/`, /proc
# and /sys read-only because reading host filesystem statistics IS its job. It
# runs a single fixed Go binary with no request surface that reaches the
# filesystem, executes nothing the model or a user can influence, and is on the
# `monitoring` profile. That is a different thing from a gateway that evaluates
# model-authored tool calls. If it ever grows one, this exemption is wrong.
EXEMPT_SERVICES = {"node-exporter"}


def _mounts() -> list[tuple[str, str, str]]:
    """(compose file, service, source) for every bind mount with an absolute source."""
    out: list[tuple[str, str, str]] = []
    for name in COMPOSE_FILES:
        path = ROOT / name
        # Every listed file must exist: a silent skip is how the evolve
        # overlay went unchecked under its old name for months.
        assert path.is_file(), f"{name} is listed but not in the tree"
        doc = __import__('tests._compose_projection', fromlist=['untag']).untag(__import__('tests._compose_projection', fromlist=['load_raw']).load_raw(path)) or {}
        for svc, body in (doc.get("services") or {}).items():
            for v in (body or {}).get("volumes") or []:
                src = v.split(":")[0] if isinstance(v, str) else (v.get("source") or "")
                if src.startswith("/"):
                    out.append((name, svc, src))
    return out


def test_the_parser_actually_found_mounts() -> None:
    """Guard the guard: a rename that makes `_mounts()` return nothing would
    turn every assertion below into a vacuous pass."""
    found = _mounts()
    assert len(found) >= 3, f"expected several absolute bind mounts, found {found}"
    assert any(src == "/" for _, _, src in found), (
        "the parser no longer sees node-exporter's root mount, so it would not "
        "see a reintroduced one either"
    )


def test_no_service_mounts_a_whole_host_tree() -> None:
    forbidden = {p.rstrip("/") or "/" for p in FORBIDDEN}
    bad = [
        (f, svc, src)
        for f, svc, src in _mounts()
        if svc not in EXEMPT_SERVICES and (src.rstrip("/") or "/") in forbidden
    ]
    assert not bad, (
        "compose mounts a whole host tree into a container — see tracker R22:\n"
        + "\n".join(f"  {f}: {svc} <- {src}" for f, svc, src in bad)
    )


def test_the_host_fs_bind_is_gone() -> None:
    """The specific shape that existed, named so a revert is unambiguous."""
    for name in COMPOSE_FILES:
        path = ROOT / name
        # Every listed file must exist: a silent skip is how the evolve
        # overlay went unchecked under its old name for months.
        assert path.is_file(), f"{name} is listed but not in the tree"
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue  # the history is allowed to be written down
            assert "/host-fs/" not in stripped, f"{name}: {stripped}"
