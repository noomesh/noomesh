# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The slim images' dependency set must carry what the code imports.

Live 2026-10-06 (v0.2.93): noo-worker booted with SQLAlchemy 2.1.3 and no
greenlet. SQLAlchemy 2.1 made greenlet an extra-only dependency, the `db`
extra named bare ``sqlalchemy``, and ``sqlalchemy.ext.asyncio`` (db.engine,
the audit sink) needs greenlet at first use -- so every audit DB write failed
and the heartbeat scheduler never initialised.

These tests resolve each image's extras closure from the Dockerfiles +
pyproject and fail when async SQLAlchemy is imported without greenlet.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
EXTRAS = PYPROJECT["project"]["optional-dependencies"]
BASE_DEPS = PYPROJECT["project"].get("dependencies", [])

# Every image that pip-installs the noomesh package, and the file doing it.
INSTALLERS = ["docker/Dockerfile.deps-core", "docker/Dockerfile.deps-base", "Dockerfile"]


def _closure(extras: set[str]) -> list[Requirement]:
    """All requirements reachable from `noomesh[extras]`, self-refs expanded."""
    seen: set[str] = set()
    reqs: list[Requirement] = [Requirement(r) for r in BASE_DEPS]
    todo = list(extras)
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        for raw in EXTRAS[name]:
            r = Requirement(raw)
            if r.name == "noomesh":
                todo.extend(r.extras)
            else:
                reqs.append(r)
    return reqs


def _installed_extras(dockerfile: str) -> set[str]:
    text = (ROOT / dockerfile).read_text()
    found: set[str] = set()
    for m in re.finditer(r'"?\.\[([a-z0-9,_-]+)\]"?', text):
        found |= {e for e in m.group(1).split(",") if e}
    return found


def _provides_greenlet(reqs: list[Requirement]) -> bool:
    for r in reqs:
        if r.name == "greenlet":
            return True
        if r.name == "sqlalchemy" and "asyncio" in r.extras:
            return True
    return False


def test_src_really_imports_async_sqlalchemy() -> None:
    """Premise check: if this goes quiet the other tests guard nothing."""
    users = [
        p for p in (ROOT / "src").rglob("*.py")
        if "sqlalchemy.ext.asyncio" in p.read_text(errors="replace")
    ]
    assert len(users) >= 2, users


def test_each_image_install_line_was_parsed() -> None:
    for df in INSTALLERS:
        assert _installed_extras(df), f"parse found no extras in {df}"


def test_every_image_that_installs_noomesh_gets_greenlet() -> None:
    for df in INSTALLERS:
        reqs = _closure(_installed_extras(df))
        if not any(r.name == "sqlalchemy" for r in reqs):
            continue  # image has no SQLAlchemy at all
        assert _provides_greenlet(reqs), (
            f"{df} installs sqlalchemy without the [asyncio] extra (no greenlet); "
            "sqlalchemy.ext.asyncio then fails at first use on SQLAlchemy >= 2.1"
        )


def test_worker_image_closure_has_sqlalchemy_asyncio() -> None:
    """The worker FROMs deps-core: pin that the db tier is in it at all."""
    reqs = _closure(_installed_extras("docker/Dockerfile.deps-core"))
    assert any(r.name == "sqlalchemy" for r in reqs), "deps-core lost its db tier"
    assert _provides_greenlet(reqs)


def test_every_declared_sqlalchemy_requirement_includes_asyncio() -> None:
    for extra, raws in EXTRAS.items():
        for raw in raws:
            r = Requirement(raw)
            if r.name == "sqlalchemy":
                assert "asyncio" in r.extras, f"[{extra}] declares bare {raw!r}"
