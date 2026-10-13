# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The namespace this repo builds into is declared once, and the cleaner uses it.

`scripts/noomesh-clean.sh --images` pruned `--filter "reference=pai-assistant/*"`
from before 2026-09-06, when `10fb1cd1` renamed the local build namespace to
`noomesh`. After the rename that filter matched nothing: `--images` removed
nothing and printed "Custom images removed". A cleanup that reports success
having done nothing is worse than one that fails — the operator moves on
believing the disk is reclaimed, and every current local image stays.

The same rename stranded five scripts that ran containers from the dead name
(see `test_scripts_do_not_docker_run_local_build_names.py`). A namespace
spelled out in N places is a rename with N chances to be missed, so it is
declared once, in `scripts/lib-dist.sh::local_image_namespace`, and this test
pins that declaration against what the compose files actually build. Tracker
R42.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
LIB = REPO / "scripts/lib-dist.sh"
CLEAN = REPO / "scripts/noomesh-clean.sh"


def _shell(expr: str) -> str:
    """Evaluate a helper from lib-dist.sh, so the test reads the DEFINITION
    rather than a regex over it."""
    res = subprocess.run(
        ["bash", "-c", f'. "{LIB}"; {expr}'],
        capture_output=True, text=True, timeout=60, cwd=REPO,
    )
    assert res.returncode == 0, res.stderr
    return res.stdout.strip()


def _compose_build_namespaces() -> set[str]:
    """Namespaces every `build:`-ing compose service tags its image into."""
    doc = yaml.safe_load((REPO / "docker-compose.cluster.yml").read_text()) or {}
    out: set[str] = set()
    for body in (doc.get("services") or {}).values():
        body = body or {}
        if "build" not in body:
            continue
        image = body.get("image", "")
        # Only unqualified `<ns>/<name>:<tag>` forms are local build tags; an
        # interpolated ${NOO_IMAGE_PREFIX...} one is a release pin.
        m = re.match(r"^([a-z0-9][a-z0-9._-]*)/[a-z0-9._-]+:[A-Za-z0-9._-]+$", image)
        if m:
            out.add(m.group(1))
    return out


def test_the_parser_found_local_build_tags() -> None:
    """Guard the guard: an empty set would make the comparison vacuous."""
    ns = _compose_build_namespaces()
    assert ns, "no unqualified local build image tags found in docker-compose.cluster.yml"


def test_the_declared_namespace_is_what_compose_builds() -> None:
    declared = _shell("local_image_namespace")
    assert declared, "local_image_namespace printed nothing"
    assert _compose_build_namespaces() == {declared}, (
        f"compose builds into {_compose_build_namespaces()} but lib-dist.sh declares "
        f"{declared!r} — a rename that missed one of them"
    )


def test_the_cleaner_derives_its_filter_from_that_declaration() -> None:
    body = CLEAN.read_text()
    code = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    joined = "\n".join(code)
    assert "lib-dist.sh" in joined, "noomesh-clean.sh does not source lib-dist.sh"
    assert "local_image_namespace" in joined, (
        "the --images filter does not come from local_image_namespace"
    )
    # The literal that went stale must not be back in the executable part.
    assert "reference=pai-assistant/*" not in joined, (
        "the hardcoded stale filter is back in noomesh-clean.sh"
    )
    # It must still reach the legacy layers: they are what an old box has, and
    # this is the only thing that will ever remove them.
    assert "legacy_image_namespaces" in joined


def test_the_legacy_namespace_is_still_declared() -> None:
    """Cleanup has to know the old name even though nothing builds it.

    If this ever returns empty, a box onboarded before 2026-09-06 keeps its
    stale layers forever with nothing to find them.
    """
    assert _shell("legacy_image_namespaces") == "pai-assistant"


def test_resolve_release_image_uses_the_same_declaration() -> None:
    """Builder, runner and pruner cannot disagree again."""
    declared = _shell("local_image_namespace")
    assert _shell("resolve_release_image postgres-pgvector") == (
        f"{declared}/postgres-pgvector:latest"
    )
    # And a dist install overrides it wholesale.
    assert _shell(
        'NOO_IMAGE_PREFIX=ghcr.io/noomesh NOO_IMAGE_TAG=v1.2.3 '
        "resolve_release_image postgres-pgvector"
    ) == "ghcr.io/noomesh/postgres-pgvector:v1.2.3"
