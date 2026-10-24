# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launchers refuse to start onto a closed encrypted state volume (i10a).

When a controller's state (postgres, redis, nats, prometheus, grafana, loki,
noo-data) lives on the TPM-unlocked LUKS2 volume and that volume did not open
— a failed TPM unlock after a firmware change, a moved disk — starting the
stack would run every service on an empty directory. The criterion lives in
the `noo` binary (`noo config launch-check state-root`,
noo-cli/src/commands/at_rest_volume.rs, unit-tested there on fake mount
tables); scripts/lib-state-volume.sh `check_state_volume_open` only runs it
and maps its exit code, like check_secrets_at_rest.

  1. GUARD (no tools): every launcher sources the lib and calls
     `check_state_volume_open || exit 1` before its first `docker compose`;
     the CLI embeds the lib (a standalone install has no tree); hostd's boot
     restore checks it too.
  2. GLUE (bash only; fake `noo`): exit 3 refuses and noo's lines reach
     stderr; 0 passes; an older noo (exit 2) or no noo at all WARNS and lets
     the start continue; the install root handed over is the launcher's cwd.
"""

from __future__ import annotations

import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB = SCRIPTS / "lib-state-volume.sh"
LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")

CALL_LINE = re.compile(r"^\s*check_state_volume_open\s*\|\|\s*exit 1\s*$")
SOURCE_LINE = re.compile(r"^\s*(source|\.)\s+\S*lib-state-volume\.sh\"?\s*$")
SECRETS_LINE = re.compile(r"^\s*check_secrets_at_rest\s*\|\|\s*exit 1\s*$")
COMPOSE_LINE = re.compile(r"\bdocker compose\b")


def _statements(path: Path) -> list[str]:
    return [l for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]


# ── 1. guard ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", LAUNCHERS)
def test_every_launcher_checks_the_state_volume_before_compose(name):
    stmts = _statements(SCRIPTS / name)
    calls = [i for i, s in enumerate(stmts) if CALL_LINE.match(s)]
    assert calls, f"{name} never calls `check_state_volume_open || exit 1`"
    sources = [i for i, s in enumerate(stmts) if SOURCE_LINE.match(s)]
    assert sources and sources[0] < calls[0], f"{name}: lib-state-volume.sh is not sourced before the call"
    secrets = [i for i, s in enumerate(stmts) if SECRETS_LINE.match(s)]
    assert secrets and secrets[0] < calls[0], f"{name}: the check rides beside check_secrets_at_rest"
    composes = [i for i, s in enumerate(stmts) if COMPOSE_LINE.search(s)]
    assert composes, f"{name}: found no `docker compose` line — the pattern broke"
    assert calls[0] < composes[0], f"{name}: `{stmts[composes[0]].strip()}` runs before the state-volume check"


def test_the_lib_does_not_restate_the_criterion():
    body = LIB.read_text()
    fn = body[body.index("check_state_volume_open() {"):]
    fn = fn[: fn.index("\n}\n")]
    assert "config launch-check state-root ." in fn
    for word in ("/proc/mounts", "at-rest.json", "cryptsetup", "/dev/mapper"):
        assert word not in fn, f"check_state_volume_open restates the criterion ({word})"


def test_the_cli_embeds_the_lib_and_hostd_boot_restore_calls_it():
    build = (REPO_ROOT / "noo-cli" / "build.rs").read_text()
    assert '"scripts/lib-state-volume.sh",' in build, "a standalone install would have no lib-state-volume.sh"
    boot = (REPO_ROOT / "node-agent-go" / "internal" / "hostd" / "boot.go").read_text()
    assert "lib-state-volume.sh" in boot and "check_state_volume_open" in boot


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
        pwd > "$FAKE_NOO_RECORD.cwd"
        [ -n "${FAKE_NOO_STDERR:-}" ] && echo "$FAKE_NOO_STDERR" >&2
        exit "${FAKE_NOO_RC:-0}"
        """)
    # HOME is the empty tmp dir: the lib's ~/.local/bin/noo fallback must not
    # find this machine's real noo.
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home"), "TERM": "dumb", "FAKE_NOO_RECORD": str(record)}
    return {"env": env, "work": work, "record": record, "noo": tmp_path / "noo"}


def _run_check(g, noo: Path | None, extra: dict | None = None):
    env = dict(g["env"])
    if noo is not None:
        env["NOO_CLI_BIN"] = str(noo)
    env.update(extra or {})
    script = f"""
set -e
source {LIB}
rc=0; check_state_volume_open || rc=$?
echo "RC=$rc"
"""
    return subprocess.run(["bash", "-c", script], cwd=g["work"], env=env, capture_output=True, text=True, timeout=30)


def test_a_refusal_refuses_and_its_lines_reach_stderr(glue):
    msg = "REFUSED: not starting — the encrypted state volume is not open"
    out = _run_check(glue, glue["noo"], {"FAKE_NOO_RC": "3", "FAKE_NOO_STDERR": msg})
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert msg in out.stderr


def test_a_pass_names_the_launcher_cwd(glue):
    out = _run_check(glue, glue["noo"])
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    argv = Path(str(glue["record"]) + ".argv").read_text().split()
    assert argv == ["config", "launch-check", "state-root", "."], argv
    assert Path(str(glue["record"]) + ".cwd").read_text().strip() == str(glue["work"])
    assert "WARNING" not in out.stderr


def test_an_older_noo_warns_and_does_not_block(glue):
    out = _run_check(glue, glue["noo"], {"FAKE_NOO_RC": "2"})
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "NOT checked" in out.stderr and "exit 2" in out.stderr, out.stderr


def test_no_noo_warns_and_does_not_block(glue):
    out = _run_check(glue, None)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "no noo binary found" in out.stderr


def test_the_home_fallback_finds_a_user_local_noo(glue, tmp_path):
    # hostd's user unit may not have ~/.local/bin on PATH.
    local = tmp_path / "home" / ".local" / "bin"
    local.mkdir(parents=True)
    _exe(local / "noo", (glue["noo"]).read_text())
    out = _run_check(glue, None, {"FAKE_NOO_RC": "3", "FAKE_NOO_STDERR": "REFUSED"})
    assert "RC=1" in out.stdout, out.stdout + out.stderr


# ── 3. hostd boot restore, run for real ──────────────────────────────────


def _boot_script(lib_secrets: Path) -> str:
    go = (REPO_ROOT / "node-agent-go" / "internal" / "hostd" / "boot.go").read_text()
    m = re.search(r"const bootRestoreScript = `(.*?)`\n", go, re.S)
    assert m, "bootRestoreScript not found"
    assert m.group(1).count("%s") == 1, "one placeholder: lib-state-volume.sh is found beside lib-secrets.sh"
    return m.group(1).replace("%s", f"'{lib_secrets}'")


@pytest.fixture
def boot(glue, tmp_path):
    libdir = tmp_path / "scripts"
    libdir.mkdir()
    (libdir / "lib-state-volume.sh").write_text(LIB.read_text())
    (libdir / "lib-data-root-mount.sh").write_text((SCRIPTS / "lib-data-root-mount.sh").read_text())
    marker = tmp_path / "secrets-written"
    lib_secrets = libdir / "lib-secrets.sh"
    lib_secrets.write_text(
        f'secret_rundir() {{ echo "{tmp_path}/rundir"; }}\n'
        f'load_secrets() {{ mkdir -p "{tmp_path}/rundir"; touch "{marker}"; }}\n'
    )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    dlog = tmp_path / "docker.log"
    _exe(bindir / "docker", f"""\
        #!/bin/sh
        echo "$@" >> "{dlog}"
        """)
    env = dict(glue["env"], PATH=f"{bindir}:/usr/bin:/bin", NOO_CLI_BIN=str(glue["noo"]))
    return {"script": _boot_script(lib_secrets), "env": env, "marker": marker, "dlog": dlog, "work": glue["work"]}


def _boot_run(b, rc: str):
    env = dict(b["env"], FAKE_NOO_RC=rc, FAKE_NOO_STDERR="REFUSED: not starting — the encrypted state volume is not open")
    return subprocess.run(["bash", "-c", b["script"]], cwd=b["work"], env=env, capture_output=True, text=True, timeout=30)


def test_boot_restore_starts_nothing_onto_a_closed_volume(boot):
    r = _boot_run(boot, "3")
    assert r.returncode == 3, (r.stdout, r.stderr)
    assert "encrypted state volume is not open" in r.stderr
    assert not boot["marker"].exists(), "secrets were written for a stack that must not start"
    assert not boot["dlog"].exists(), "docker was called"


def test_boot_restore_proceeds_when_the_volume_is_open(boot):
    r = _boot_run(boot, "0")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert boot["marker"].exists()
    assert "ps -aq" in boot["dlog"].read_text()
