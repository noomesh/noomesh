# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The shipped Python image installs from a hash-locked file, not from ranges.

`pyproject.toml` declares `>=` ranges, so an unlocked `uv pip install -e .[...]`
resolves whatever PyPI serves on build day: a release published after review
(or a hijacked one) enters the image with no hash to refuse it. The shipped
install set is `docker/core-lock/requirements.txt`, installed with `--require-hashes`.
This guard fails if Dockerfile.deps-core goes back to resolving from ranges,
if the lock loses its hashes, or if the extras the Dockerfile used to name and
the extras the lock was compiled for drift apart.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker" / "Dockerfile.deps-core"
LOCK = ROOT / "docker" / "core-lock" / "requirements.txt"


def _install_commands() -> list[str]:
    """Each RUN instruction of the Dockerfile that installs Python packages,
    with line continuations joined."""
    text = DOCKERFILE.read_text().replace("\\\n", " ")
    runs = [l for l in text.splitlines() if l.startswith("RUN ")]
    found = [r for r in runs if "pip install" in r]
    assert found, "parse found no `pip install` RUN in Dockerfile.deps-core"
    return found


def test_dockerfile_installs_from_the_hash_lock() -> None:
    cmds = _install_commands()
    locked = [c for c in cmds if "-r /tmp/requirements-core.txt" in c]
    assert locked, "deps-core must install third-party packages from the lock"
    for c in locked:
        assert "--require-hashes" in c, f"lock install without --require-hashes: {c}"
    # Anything else that installs must not resolve from ranges: only the
    # project itself, editable, with --no-deps, is allowed.
    for c in cmds:
        for part in re.split(r"&&|;", c):
            if "pip install" not in part or "-r /tmp/requirements-core.txt" in part:
                continue
            assert "--no-deps" in part and re.search(r"-e \.(\s|$)", part), (
                f"unlocked install in deps-core resolves from pyproject ranges: {part.strip()}"
            )
            assert "[" not in part, f"extras in the unlocked project install: {part.strip()}"


def test_dockerfile_copies_the_lock_before_installing() -> None:
    text = DOCKERFILE.read_text()
    copy = text.find("COPY docker/core-lock/requirements.txt /tmp/requirements-core.txt")
    install = text.find("-r /tmp/requirements-core.txt")
    assert copy != -1 and install != -1 and copy < install


def test_every_pin_in_the_lock_carries_hashes() -> None:
    text = LOCK.read_text().replace("\\\n", " ")
    pins = [
        l for l in text.splitlines()
        if l and not l.startswith(("#", " ")) and "==" in l
    ]
    assert len(pins) > 20, f"lock parse found only {len(pins)} pins"
    for l in pins:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", l), f"pin without a sha256 hash: {l[:60]}"
    assert not re.search(r"^\s*(-e|git\+|https?://)", LOCK.read_text(), re.M), (
        "lock must contain registry pins only"
    )


def test_lock_header_extras_cover_the_pyproject_extras_the_image_needs() -> None:
    header = "\n".join(l for l in LOCK.read_text().splitlines() if l.startswith("#"))
    for extra in ("web", "cache", "feedback", "pgvector", "mcp"):
        assert f"--extra {extra}" in header, f"lock header lost --extra {extra}"
    # ML extras belong to Dockerfile.deps-base, never the core lock.
    for extra in ("trellion", "rag", "voice"):
        assert f"--extra {extra}" not in header
