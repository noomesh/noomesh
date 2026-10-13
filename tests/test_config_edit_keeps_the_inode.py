# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A launcher edit of noomesh.yaml must not replace the file.

`sed -i` renames a temp file over the target. noomesh.yaml is bind-mounted
into the containers as a single file, so the rename orphans the mount: the
containers keep the unlinked inode, the host path is a new one, and the next
recreate silently discards the change. `noomesh-start.sh` promoted
NOO_IMAGE_TAG with `sed -i`. These tests run the real helper and compare
inodes, because the bug is invisible in the file's content.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-config.sh"
START = ROOT / "scripts" / "noomesh-start.sh"
EXPR = r"s|^([[:space:]]*NOO_IMAGE_TAG:).*|\1 stack-v9|"


def run_edit(path: Path, expr: str = EXPR) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f'. "{LIB}"; config_sed_in_place "$1" "$2"', "_", str(path), expr],
        capture_output=True,
        text=True,
    )


def test_edit_changes_content_and_keeps_the_inode(tmp_path: Path) -> None:
    f = tmp_path / "noomesh.yaml"
    f.write_text("compose_env:\n  NOO_IMAGE_TAG: stack-v1\n  OTHER: x\n")
    ino = f.stat().st_ino
    held = open(f)  # stands in for the container's bind-mount reference
    r = run_edit(f)
    assert r.returncode == 0, r.stderr
    assert f.stat().st_ino == ino, "the edit replaced the file: a bind mount would be orphaned"
    assert "NOO_IMAGE_TAG: stack-v9" in f.read_text()
    assert "OTHER: x" in f.read_text()
    assert "stack-v9" in held.read(), "a holder of the original inode must see the edit"
    held.close()


def test_failing_sed_leaves_the_file_untouched(tmp_path: Path) -> None:
    f = tmp_path / "noomesh.yaml"
    f.write_text("compose_env:\n  NOO_IMAGE_TAG: stack-v1\n")
    r = run_edit(f, "s|(unbalanced")
    assert r.returncode != 0
    assert f.read_text() == "compose_env:\n  NOO_IMAGE_TAG: stack-v1\n"


def test_launcher_does_not_sed_i_the_config() -> None:
    for line in START.read_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert not ("sed -i" in line and "noomesh.yaml" in line), line
