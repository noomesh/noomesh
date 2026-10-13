# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The composed projection: what `docker compose` actually runs.

Since an earlier change an add-on can be an overlay that `extends` a base service
across files. A guard that reads one YAML file then sees a three-key
`environment:` where the container gets sixty — the parent's allowlist is
inherited at compose time, not visible in the text. Guards about what a
CONTAINER receives therefore read the projection, `docker compose config`,
with every profile selected so nothing is filtered out. `--no-interpolate`
keeps `${VAR:-default}` literal, which is the form the guards compare.

Real compose, not a re-implementation: the merge rules (`extends`, `!reset`,
`!override`, list-vs-map environment) are compose's to define, and a Python
copy of them would be a second home that drifts.
"""

from __future__ import annotations

import functools
import re
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "docker-compose.cluster.yml"
# Every add-on overlay that extends or adds services to the base. Listed, not
# globbed: dist and gpu-embed are not add-ons, and the site override is
# generated.
ADDON_OVERLAYS = (
    "docker-compose.trellion.yml",
    "docker-compose.trellion-intel.yml",
    "docker-compose.voice.yml",
    "docker-compose.evolve.yml",
)


class _TagTolerantLoader(yaml.SafeLoader):
    """Reads compose files that use `!reset` / `!override` (compose ≥ 2.24)
    for what they SAY, keeping the tag as a marker. Only for shape checks on
    one file; anything about the result goes through `projection`."""


def _tagged(loader, tag_suffix, node):
    if isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        value = loader.construct_scalar(node)
    return {"!tag": tag_suffix, "value": value}


_TagTolerantLoader.add_multi_constructor("!", _tagged)


def load_raw(path: Path) -> dict:
    """One file as written, tags preserved as `{"!tag": ..., "value": ...}`."""
    return yaml.load(path.read_text(), Loader=_TagTolerantLoader) or {}


def untag(value):
    """Strip tag markers for callers that only care about the value."""
    if isinstance(value, dict):
        if set(value) == {"!tag", "value"}:
            return untag(value["value"])
        return {k: untag(v) for k, v in value.items()}
    if isinstance(value, list):
        return [untag(v) for v in value]
    return value


def _profiles_in(*files: Path) -> set[str]:
    out: set[str] = set()
    for f in files:
        for svc in (untag(load_raw(f)).get("services") or {}).values():
            out.update(svc.get("profiles") or [])
    return out


# `config --no-interpolate` parses short-syntax volumes with the `${VAR:-x}`
# text still in them; compose < 2.40 rejects `${NOO_PKI_DIR:-./.pki-placeholder}:/tls:ro`
# as "too many colons" (bisected 2026-09-22: 2.36 and 2.39 fail, 2.40.3 and
# 5.0 pass). CI pins a version at or above this; a developer below it gets
# this message, not a skip.
COMPOSE_FLOOR = (2, 40, 0)


def _compose_version() -> tuple[int, ...]:
    out = subprocess.run(
        ["docker", "compose", "version", "--short"], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, f"docker compose version failed: {out.stderr}"
    raw = out.stdout.strip().lstrip("v")
    return tuple(int(x) for x in re.findall(r"\d+", raw)[:3])


@functools.lru_cache(maxsize=None)
def _require_compose_floor() -> None:
    v = _compose_version()
    assert v >= COMPOSE_FLOOR, (
        f"docker compose {'.'.join(map(str, v))} is below the {'.'.join(map(str, COMPOSE_FLOOR))} "
        "floor this guard needs for `config --no-interpolate` — upgrade the compose plugin "
        "(the controller runs v5)"
    )


@functools.lru_cache(maxsize=None)
def projection(*overlays: str) -> dict:
    """`docker compose config --no-interpolate` over the base plus `overlays`
    (names relative to the repo root), every profile selected."""
    assert shutil.which("docker"), (
        "docker is not on PATH — this guard reads the composed projection and "
        "cannot run without `docker compose`; do not skip it, install compose"
    )
    _require_compose_floor()
    files = [BASE, *(ROOT / o for o in overlays)]
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", str(f)]
    for p in sorted(_profiles_in(*files)):
        cmd += ["--profile", p]
    cmd += ["config", "--no-interpolate"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, f"{' '.join(cmd)}\n{out.stderr}"
    doc = yaml.safe_load(out.stdout) or {}
    assert doc.get("services"), "the projection has zero services — every assertion on it would be vacuous"
    return doc


def env_of(service: dict) -> dict[str, str]:
    """A service's environment as a mapping, whichever form compose rendered."""
    env = service.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return {k: ("" if v is None else str(v)) for k, v in env.items()}


def full_projection() -> dict:
    """Base + every add-on overlay: the widest stack an install can run."""
    return projection(*ADDON_OVERLAYS)


def raw_services_union() -> dict:
    """Base services plus every add-on overlay's, as WRITTEN (tags stripped,
    no extends resolution). For guards about a service's own declaration —
    which file declares what — not about what its container receives."""
    out = dict(untag(load_raw(BASE)).get("services") or {})
    for o in ADDON_OVERLAYS:
        for name, svc in (untag(load_raw(ROOT / o)).get("services") or {}).items():
            out.setdefault(name, svc)
    return out
