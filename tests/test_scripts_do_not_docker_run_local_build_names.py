# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A script that runs a container must not name a LOCAL BUILD image.

Compose services are covered by
`tests/test_release_images_are_pinned_in_compose.py`: on a dist install the
overlay pins every release image to
`${NOO_IMAGE_PREFIX}/<name>:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_<NAME>:-}`. A
shell script that calls `docker run` directly gets none of that, and three of
them hardcoded `pai-assistant/postgres-pgvector:latest`:
`restore-drill.sh`, `bootstrap-standby.sh` and `pg-upgrade.sh` (the last
retired — the PG16 → PG18
upgrade it performed is done).

That name stopped being produced on 2026-09-06, when the local namespace was
renamed to `noomesh/`. So on a dev box those scripts had been reaching for an
image that survived only as a stale cached layer, and on a `--dist` controller
neither name exists at all — `docker run` fails with "pull access denied". The
casualty found on 2026-09-12 was the backup RESTORE DRILL: the one command
that proves a backup is restorable could not start its container on a
standalone controller, which is the install most likely to need it. Tracker
R42.

The rule: a `docker run` in `scripts/` names either an upstream/public image,
or an image resolved through `lib-dist.sh::resolve_release_image` (or an
env-overridable variable). Never a bare project-local name.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

# Namespaces that only ever exist as a LOCAL `docker build` result. Neither is
# pullable from anywhere.
LOCAL_NAMESPACES = ("pai-assistant/", "noomesh/")

# `docker build -t <local-name>` is how those images come to exist, and
# `docker image inspect` / `--filter reference=` are legitimately looking for
# a local layer. Only *running* a container is covered here.
RUN_RE = re.compile(r"\bdocker\s+run\b")


def _script_lines() -> list[tuple[str, int, str]]:
    out = []
    for path in sorted(SCRIPTS.glob("*.sh")):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            out.append((f"scripts/{path.name}", n, line))
    return out


def _docker_run_commands() -> list[tuple[str, int, str]]:
    """Each `docker run` with its full (continuation-joined) command text."""
    cmds: list[tuple[str, int, str]] = []
    for path in sorted(SCRIPTS.glob("*.sh")):
        lines = path.read_text().splitlines()
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if not stripped.startswith("#") and RUN_RE.search(stripped):
                start = i
                buf = [lines[i]]
                # Follow backslash continuations, and the quoted `-c "..."`
                # bodies these scripts use, far enough to reach the image arg.
                while i < len(lines) - 1 and lines[i].rstrip().endswith("\\"):
                    i += 1
                    buf.append(lines[i])
                cmds.append((f"scripts/{path.name}", start + 1, "\n".join(buf)))
            i += 1
    return cmds


def test_the_parser_finds_the_docker_runs() -> None:
    """Guard the guard.

    A regex that silently matched nothing would make every assertion below a
    vacuous pass — and this file exists precisely because a silent miss went
    unnoticed for six days.
    """
    cmds = _docker_run_commands()
    assert len(cmds) >= 10, f"expected many `docker run` calls in scripts/, found {len(cmds)}"
    names = {c[0] for c in cmds}
    for expected in ("scripts/restore-drill.sh", "scripts/bootstrap-standby.sh"):
        assert expected in names, f"{expected} no longer parses as running a container"


def test_no_docker_run_names_a_local_build_image() -> None:
    bad = []
    for file, line, text in _docker_run_commands():
        for ns in LOCAL_NAMESPACES:
            if ns in text:
                bad.append(f"  {file}:{line} names {ns}…")
    assert not bad, (
        "a script runs a container from a project-local build name, which does not exist on a "
        "--dist install (tracker R42). Resolve it with "
        "`resolve_release_image <name>` from scripts/lib-dist.sh:\n" + "\n".join(bad)
    )


def test_the_postgres_scripts_resolve_through_the_helper() -> None:
    """Named individually, so a revert to a literal is unambiguous."""
    for name in ("restore-drill.sh", "bootstrap-standby.sh"):
        body = (SCRIPTS / name).read_text()
        assert "resolve_release_image postgres-pgvector" in body, (
            f"{name} no longer resolves the postgres image through lib-dist.sh"
        )
        assert "lib-dist.sh" in body, f"{name} does not source lib-dist.sh"


def test_the_helper_produces_both_shapes() -> None:
    """The helper is the single definition of the pin expression.

    Asserted on the source rather than by execution so this test says WHAT the
    shape is; `test_rotate_passphrase_preserves_the_store.py` and the live
    scripts exercise it for real.
    """
    body = (SCRIPTS / "lib-dist.sh").read_text()
    assert "resolve_release_image()" in body
    # Dev default and dist override in one expression, matching the compose
    # files' `${NOO_IMAGE_PREFIX:-<ns>}` / `${NOO_IMAGE_TAG:-latest}` shape.
    # The dev default is DERIVED from local_image_namespace, not spelled out
    # again — see test_image_namespace_is_one_definition.py for why.
    assert '"${NOO_IMAGE_PREFIX:-$(local_image_namespace)}"' in body
    assert '"${NOO_IMAGE_TAG:-latest}"' in body
    assert "NOO_IMAGE_DIGEST_" in body


def test_local_build_names_elsewhere_are_still_allowed() -> None:
    """This rule is about RUNNING, not building.

    `docker build -t noomesh/<x>` is how these images come to exist, and
    `docker image inspect` on a local name is a legitimate cache probe. If this
    test ever fails, the rule above has been widened past its evidence.
    """
    builds = [
        (f, n, ln)
        for f, n, ln in _script_lines()
        if "docker build" in ln and any(ns in ln for ns in LOCAL_NAMESPACES)
    ]
    # Not an assertion about the count — just that the rule does not claim
    # these are wrong.
    for f, n, ln in builds:
        assert "docker run" not in ln, f"{f}:{n} both builds and runs: {ln.strip()}"
