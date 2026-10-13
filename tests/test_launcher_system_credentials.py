# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launchers refuse to start while an enabled system lacks its credentials
 — instead of letting the gateway crash-loop.

stack-v0.2.80 rehearsal (evolve, standalone sandbox): `noo security
entitlement install <token> --enable` switched evolve on and minted nothing;
the next `noo stack restart --force` crash-looped noo-gateway (13 restarts in
two minutes) on `system "evolve" is enabled but NOO_EVOLVE_DDL_PASSWORD is
not set`. The enable paths now mint first (noo-cli commands::addon_enable);
this is the second half: a start that would crash-loop is refused before
compose moves anything, naming `noo systems enable <name>`.

The decision lives in the `noo` binary (`noo config launch-check
system-credentials`, commands::systems::launch_check, unit-tested in the
noo-cli CI job); scripts/lib-bind-sources.sh's `check_system_credentials`
only calls it.

  1. GUARD (no tools): each launcher calls `check_system_credentials ||
     exit 1` after loading secrets and before its first `docker compose`.
  2. GLUE (bash, fake `noo`): 3 refuses and the fix reaches stderr; 0
     passes; an older noo (2) or no noo warns and does not block.
  3. END TO END (debug noo): evolve on without NOO_EVOLVE_DDL_PASSWORD is
     refused naming the fix; with it exported, the start passes.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB_CONFIG = SCRIPTS / "lib-config.sh"
LIB_BIND = SCRIPTS / "lib-bind-sources.sh"
NOO_DEBUG = REPO_ROOT / "noo-cli" / "target" / "debug" / "noo"

LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")
CALL = re.compile(r"^\s*check_system_credentials\s*\|\|\s*exit 1\s*$")
COMPOSE = re.compile(r"^\s*[^#]*\bdocker compose\b")
SECRETS = re.compile(r"^\s*load_secrets\b")


# ── 1. guard ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", LAUNCHERS)
def test_each_launcher_checks_system_credentials_before_any_compose(name):
    lines = (SCRIPTS / name).read_text().splitlines()
    calls = [i for i, line in enumerate(lines) if CALL.match(line)]
    assert len(calls) == 1, f"{name}: expected one `check_system_credentials || exit 1`, found {len(calls)}"
    loads = [i for i, line in enumerate(lines) if SECRETS.match(line)]
    assert loads and loads[0] < calls[0], f"{name}: the check runs before load_secrets — it would see no store"
    composes = [i for i, line in enumerate(lines) if COMPOSE.match(line)]
    assert composes, f"{name}: found no `docker compose` line — the pattern broke"
    assert calls[0] < composes[0], (
        f"{name}: `{lines[composes[0]].strip()}` (line {composes[0] + 1}) runs before the credential "
        f"check (line {calls[0] + 1})"
    )


# ── 2. glue ──────────────────────────────────────────────────────────────


def _exe(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def glue(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    record = tmp_path / "record"
    _exe(tmp_path / "noo", """\
        #!/usr/bin/env bash
        printf '%s\\n' "$*" > "$FAKE_NOO_RECORD.argv"
        [ -n "${FAKE_NOO_STDERR:-}" ] && echo "$FAKE_NOO_STDERR" >&2
        exit "${FAKE_NOO_RC:-0}"
        """)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "TERM": "dumb", "FAKE_NOO_RECORD": str(record)}
    return {"env": env, "work": work, "record": record, "noo": tmp_path / "noo"}


def _run(g, noo: bool = True, extra: dict | None = None):
    env = dict(g["env"])
    if noo:
        env["NOO_CLI_BIN"] = str(g["noo"])
    env.update(extra or {})
    script = f"""
source {LIB_CONFIG}
source {LIB_BIND}
rc=0; check_system_credentials || rc=$?
echo "RC=$rc"
"""
    return subprocess.run(["bash", "-c", script], cwd=g["work"], env=env,
                          capture_output=True, text=True, timeout=30)


def test_a_refusal_refuses_and_names_the_fix(glue):
    out = _run(glue, extra={"FAKE_NOO_RC": "3", "FAKE_NOO_STDERR": "fix: noo systems enable evolve"})
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "noo systems enable evolve" in out.stderr
    argv = Path(str(glue["record"]) + ".argv").read_text().split()
    assert argv == ["config", "launch-check", "system-credentials", "noomesh.yaml"], argv


def test_a_clean_check_passes_quietly(glue):
    out = _run(glue)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "WARNING" not in out.stderr


def test_an_older_noo_warns_and_does_not_block(glue):
    out = _run(glue, extra={"FAKE_NOO_RC": "2"})
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "NOT checked" in out.stderr and "exit 2" in out.stderr


def test_no_noo_warns_and_does_not_block(glue):
    out = _run(glue, noo=False)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "no noo binary found" in out.stderr


# ── 3. end to end ────────────────────────────────────────────────────────

needs_noo = pytest.mark.skipif(not NOO_DEBUG.is_file(), reason="needs the debug noo (cargo build in noo-cli)")

CONFIG = """\
addons:
  evolve: true
systems:
  evolve:
    role: noo_evolve
    ddl_role: noo_evolve_ddl
    schema: evolve
    password_env: NOO_EVOLVE_DB_PASSWORD
    ddl_password_env: NOO_EVOLVE_DDL_PASSWORD
"""


def _e2e(work: Path, extra: dict):
    script = f"""
source {LIB_CONFIG}
source {LIB_BIND}
rc=0; check_system_credentials || rc=$?
echo "RC=$rc"
"""
    env = {k: v for k, v in os.environ.items() if not k.startswith("NOO_EVOLVE_")}
    env.update({"NOO_CLI_BIN": str(NOO_DEBUG), "NOO_REPO_ROOT": str(work), "HOME": str(work)})
    env.update(extra)
    return subprocess.run(["bash", "-c", script], cwd=work, env=env, capture_output=True, text=True, timeout=60)


@needs_noo
def test_e2e_enabled_evolve_without_its_ddl_password_is_refused(tmp_path):
    (tmp_path / "noomesh.yaml").write_text(CONFIG)
    out = _e2e(tmp_path, {"NOO_EVOLVE_DB_PASSWORD": "x"})
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "NOO_EVOLVE_DDL_PASSWORD" in out.stderr and "fix: noo systems enable evolve" in out.stderr, out.stderr


@needs_noo
def test_e2e_with_both_credentials_the_start_passes(tmp_path):
    (tmp_path / "noomesh.yaml").write_text(CONFIG)
    out = _e2e(tmp_path, {"NOO_EVOLVE_DB_PASSWORD": "x", "NOO_EVOLVE_DDL_PASSWORD": "y"})
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "REFUSED" not in out.stderr and "WARNING" not in out.stderr, out.stderr
