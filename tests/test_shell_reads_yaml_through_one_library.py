# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shell reads and edits noomesh.yaml through scripts/lib-config.sh only.

The launcher used to grep/awk the file in three places; a quoted value, a
trailing comment or a same-named nested key read wrong (`NOO_IMAGE_TAG:
"v0.6.7" # pin` came back as `"v0.6.7"`). These tests run the REAL shell
functions against the real yaml shapes: the shipped example, quoted and
commented values, a nested key of the same name, flow style and absence.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
LIB = SCRIPTS / "lib-config.sh"
LIB_SECRETS = SCRIPTS / "lib-secrets.sh"

SHAPES = """\
# a comment mentioning NOO_IMAGE_TAG: wrong
cluster:
  NOO_IMAGE_TAG: nested-wrong
compose_env:
  OTHER: x   # NOO_IMAGE_TAG: also wrong
  NOO_IMAGE_TAG: "v0.6.7" # pin
  PORT: 8080
addons:
  voice: false
"""


def _env(tmp: Path, noo: Path | None = None) -> dict[str, str]:
    # python3 (with PyYAML) on PATH, no `noo`: exercises the fallback reader.
    env = {"PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin", "HOME": str(tmp)}
    if noo:
        env["NOO_CLI_BIN"] = str(noo)
    return env


def _sh(tmp: Path, body: str, noo: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f'cd "{tmp}" && . "{LIB}" && {body}'],
        env=_env(tmp, noo), capture_output=True, text=True, timeout=30,
    )


def _fake_noo(tmp: Path, rendered: str) -> Path:
    fake = tmp / "fake-noo"
    fake.write_text("#!/bin/sh\ncat <<'OUT'\n" + rendered + "OUT\n")
    fake.chmod(0o755)
    return fake


def test_get_strips_quotes_and_comments_and_ignores_nested_lookalikes(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text(SHAPES)
    r = _sh(tmp_path, "config_compose_env_get noomesh.yaml NOO_IMAGE_TAG")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "v0.6.7", r.stdout
    r = _sh(tmp_path, "config_compose_env_get noomesh.yaml PORT")
    assert r.stdout.strip() == "8080"


def test_get_distinguishes_absent_from_empty(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text("compose_env:\n  EMPTY: null\n  A: b\n")
    assert _sh(tmp_path, "config_compose_env_get noomesh.yaml MISSING").returncode == 1
    r = _sh(tmp_path, "config_compose_env_get noomesh.yaml EMPTY")
    assert r.returncode == 0, "present-but-empty must not read as absent"
    (tmp_path / "noomesh.yaml").write_text("cluster:\n  NOO_IMAGE_TAG: only-nested\n")
    assert _sh(tmp_path, "config_compose_env_get noomesh.yaml NOO_IMAGE_TAG").returncode == 1


def test_get_through_noo_uses_the_rendered_lines(tmp_path: Path) -> None:
    (tmp_path / "noomesh.yaml").write_text(SHAPES)
    noo = _fake_noo(tmp_path, "OTHER=x\nNOO_IMAGE_TAG=v9\n")
    r = _sh(tmp_path, "config_compose_env_get noomesh.yaml NOO_IMAGE_TAG", noo)
    assert r.stdout.strip() == "v9", "noo's parser is preferred over the python fallback"


def test_set_rewrites_only_the_compose_env_key_keeps_comment_and_inode(tmp_path: Path) -> None:
    f = tmp_path / "noomesh.yaml"
    f.write_text(SHAPES)
    ino = f.stat().st_ino
    held = open(f)
    r = _sh(tmp_path, "config_compose_env_set noomesh.yaml NOO_IMAGE_TAG stack-v9")
    assert r.returncode == 0, r.stderr
    assert f.stat().st_ino == ino, "the edit replaced the file: a bind mount would be orphaned"
    text = f.read_text()
    assert "  NOO_IMAGE_TAG: stack-v9 # pin\n" in text
    assert "  NOO_IMAGE_TAG: nested-wrong\n" in text, "a same-named key under another section is untouched"
    assert "# a comment mentioning NOO_IMAGE_TAG: wrong" in text
    assert "stack-v9" in held.read()
    held.close()
    assert _sh(tmp_path, "config_compose_env_get noomesh.yaml NOO_IMAGE_TAG").stdout.strip() == "stack-v9"


def test_set_refuses_a_missing_key_and_leaves_the_file_alone(tmp_path: Path) -> None:
    f = tmp_path / "noomesh.yaml"
    body = "cluster:\n  NOO_IMAGE_TAG: nested\ncompose_env:\n  A: b\n"
    f.write_text(body)
    r = _sh(tmp_path, "config_compose_env_set noomesh.yaml NOO_IMAGE_TAG stack-v9")
    assert r.returncode == 1
    assert f.read_text() == body


def test_fallback_reader_agrees_with_the_rust_golden_output(tmp_path: Path) -> None:
    """The python fallback must read every committed fixture the way `noo config
    launch-render compose-env` does (the goldens are that command's output)."""
    checked = 0
    for case in sorted((ROOT / "tests" / "fixtures" / "launch_render").iterdir()):
        golden = case / "compose-env.out"
        if not (case / "noomesh.yaml").exists() or not golden.exists():
            continue
        lines = golden.read_text().splitlines()
        if not lines or any(line.startswith("!ERR") for line in lines):
            continue
        (tmp_path / "noomesh.yaml").write_text((case / "noomesh.yaml").read_text())
        for line in lines:
            key, _, want = line.partition("=")
            r = _sh(tmp_path, f"config_compose_env_get noomesh.yaml {key}")
            assert r.returncode == 0 and r.stdout.rstrip("\n") == want, (case.name, line, r.stdout, r.stderr)
            checked += 1
    assert checked >= 5, "no fixture key was compared: this test would pass on nothing"


def test_has_section_is_a_top_level_probe(tmp_path: Path) -> None:
    f = tmp_path / "noomesh.yaml"
    for body, want in (
        ("systems: {}\n", 0), ("systems:\n  a: 1\n", 0), ('"systems":\n  a: 1\n', 0),
        ("cluster:\n  systems:\n    a: 1\n", 1), ("# systems:\n", 1), ("addons: {}\n", 1),
    ):
        f.write_text(body)
        assert _sh(tmp_path, "config_has_section noomesh.yaml systems").returncode == want, body


def test_lib_secrets_loads_the_probe_on_its_own(tmp_path: Path) -> None:
    """lib-secrets is sourced alone by several scripts; it must pull in the probe."""
    r = subprocess.run(
        ["bash", "-c", f'. "{LIB_SECRETS}" && type config_has_section >/dev/null && echo ok'],
        env=_env(tmp_path), capture_output=True, text=True, timeout=30, cwd=tmp_path,
    )
    assert r.stdout.strip().endswith("ok"), r.stderr


def test_no_script_parses_noomesh_yaml_with_grep_or_awk() -> None:
    scanned = 0
    offenders = []
    for path in sorted(SCRIPTS.glob("*.sh")):
        if path.name == "lib-config.sh":
            continue  # the one owner
        scanned += 1
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if re.search(r"\b(grep|awk|sed)\b", line) and re.search(r"noomesh\.yaml", line):
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert scanned >= 5, "the scan found no scripts: this guard would pass on nothing"
    # noo-fetch.sh is owned by another open change; it is the only allowed leftover.
    offenders = [o for o in offenders if not o.startswith("noo-fetch.sh")]
    assert not offenders, "parse noomesh.yaml through lib-config.sh:\n" + "\n".join(offenders)
