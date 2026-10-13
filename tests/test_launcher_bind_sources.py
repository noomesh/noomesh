# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launchers refuse a `compose up` whose bind-mount sources are missing
or the wrong type — before compose touches anything.

Docker does not refuse a missing bind source: it creates it as an empty,
root-owned DIRECTORY, even where the container expects a file (stack-v0.2.78
on host8, 2026-09-29: grafana died on `read /app/pki/sso/grafana.pub: is a
directory`). The check lives in the `noo` binary
(noo-cli/src/commands/bind_sources.rs, unit-tested there in the noo-cli CI
job); scripts/lib-bind-sources.sh feeds it the launcher's own effective
compose config.

Three layers here:

  1. GUARD (no tools needed): every `docker compose … up` in a launcher is
     immediately preceded by `check_bind_sources … || exit 1`, and the
     launcher sources the lib. A new `up` added without the check fails.
  2. GLUE (bash only; fake `noo` and fake `docker`): exit 3 from noo refuses
     (function returns 1, noo's lines reach stderr); 0 passes; an older noo
     (exit 2) or no noo at all WARNS and lets the start continue; the
     rendered config reaches noo on stdin; the launcher's own placeholder
     dirs are made before the check.
  3. END TO END (needs the debug `noo` and docker compose): a scratch
     compose project — missing file source refused naming it; a directory
     where a file is expected refused with the `rmdir` remedy; everything
     present passes; a named volume is ignored.
"""

from __future__ import annotations

import os
import re
import shutil
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

# Every script that runs a stack `compose up`. bootstrap-standby.sh is the
# one other `up` under scripts/: it starts a replica postgres on a SECOND
# machine with its own argv array and no lib-config/noo — see EXEMPT.
LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")
EXEMPT = {
    "bootstrap-standby.sh": "standby-postgres bootstrap on another host; not a stack launcher (no noo_bin, own COMPOSE_ARGS)",
}

UP_LINE = re.compile(r"^\s*docker compose\b.*\bup\b")
CHECK_LINE = re.compile(r"^\s*check_bind_sources\b.*\|\|\s*exit 1\s*$")


def _statements(path: Path) -> list[str]:
    """Non-blank, non-comment lines, and not shellcheck directives."""
    out = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(line)
    return out


# ── 1. guard ─────────────────────────────────────────────────────────────


def test_every_launcher_up_is_preceded_by_the_bind_source_check():
    seen = 0
    for name in LAUNCHERS:
        path = SCRIPTS / name
        text = path.read_text()
        assert "lib-bind-sources.sh" in text, f"{name} does not source lib-bind-sources.sh"
        stmts = _statements(path)
        for i, line in enumerate(stmts):
            if UP_LINE.match(line):
                seen += 1
                prev = stmts[i - 1] if i else ""
                assert CHECK_LINE.match(prev), (
                    f"{name}: `{line.strip()}` is not immediately preceded by "
                    f"`check_bind_sources … || exit 1` (previous statement: `{prev.strip()}`)"
                )
    # The parse must have found the ups it guards: start 2, restart 2, rebuild 2.
    assert seen >= 6, f"found only {seen} `docker compose … up` lines — the pattern broke"


def test_no_other_script_runs_compose_up_unguarded():
    for path in sorted(SCRIPTS.glob("*.sh")):
        if path.name in LAUNCHERS or path.name in EXEMPT:
            continue
        ups = [line for line in _statements(path) if UP_LINE.match(line)]
        assert not ups, (
            f"{path.name} runs `docker compose … up` without the bind-source check: {ups[0].strip()} — "
            "add `check_bind_sources … || exit 1` before it and list the script in LAUNCHERS"
        )


# ── 2. glue ──────────────────────────────────────────────────────────────

FAKE_CONFIG = '{"name":"t","services":{"a":{"volumes":[]}}}'


def _exe(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def glue(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    # docker: `compose … config --format json` prints a fixed config.
    _exe(bin_dir / "docker", f"""\
        #!/usr/bin/env bash
        case " $* " in
          *" config --format json"*) printf '%s' '{FAKE_CONFIG}' ;;
          *) echo "fake docker: unexpected $*" >&2; exit 9 ;;
        esac
        """)
    record = tmp_path / "record"
    _exe(tmp_path / "noo", """\
        #!/usr/bin/env bash
        printf '%s\\n' "$*" > "$FAKE_NOO_RECORD.argv"
        cat > "$FAKE_NOO_RECORD.stdin"
        [ -n "${FAKE_NOO_STDERR:-}" ] && echo "$FAKE_NOO_STDERR" >&2
        exit "${FAKE_NOO_RC:-0}"
        """)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "TERM": "dumb",
        "FAKE_NOO_RECORD": str(record),
        "COMPOSE_FILES": "-f docker-compose.cluster.yml",
        "PROFILE_ARGS": "--profile controller",
        "NOO_DATA_ROOT": "/srv/noo-data",
    }
    return {"env": env, "work": work, "record": record, "noo": tmp_path / "noo"}


def _run_check(g, args: str = "", noo: bool = True, extra: dict | None = None):
    env = dict(g["env"])
    if noo:
        env["NOO_CLI_BIN"] = str(g["noo"])
    env.update(extra or {})
    script = f"""
set -e
source {LIB_CONFIG}
source {LIB_BIND}
rc=0; check_bind_sources {args} || rc=$?
echo "RC=$rc"
"""
    return subprocess.run(["bash", "-c", script], cwd=g["work"], env=env,
                          capture_output=True, text=True, timeout=30)


def test_noo_refusal_refuses_and_its_lines_reach_stderr(glue):
    out = _run_check(glue, "gateway", extra={"FAKE_NOO_RC": "3", "FAKE_NOO_STDERR": "REFUSED: grafana.pub"})
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "REFUSED: grafana.pub" in out.stderr


def test_clean_check_passes_and_gets_the_config_and_args(glue):
    out = _run_check(glue, "--no-deps --skip node-agent gateway worker")
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    argv = Path(str(glue["record"]) + ".argv").read_text().split()
    assert argv[:2] == ["config", "launch-check"] and argv[2] == "bind-sources", argv
    assert argv[3:5] == ["--data-root", "/srv/noo-data"], argv
    assert argv[5:] == ["--no-deps", "--skip", "node-agent", "gateway", "worker"], argv
    assert Path(str(glue["record"]) + ".stdin").read_text() == FAKE_CONFIG
    assert "WARNING" not in out.stderr


def test_older_noo_warns_and_does_not_block_the_start(glue):
    out = _run_check(glue, extra={"FAKE_NOO_RC": "2"})
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "NOT checked" in out.stderr and "exit 2" in out.stderr


def test_no_noo_warns_and_does_not_block_the_start(glue):
    out = _run_check(glue, noo=False)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "no noo binary found" in out.stderr


def test_launcher_placeholders_are_made_before_the_check(glue):
    out = _run_check(glue, extra={
        "TRELLION_SRC": "./.trellion-src-placeholder",
        "NOO_SRC_OVERLAY": "./.src-overlay-placeholder",
        # Not a launcher placeholder: must NOT be created.
        "NOO_UI_STATIC_OVERLAY": "./src/noomesh/gateway/static",
    })
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert (glue["work"] / ".trellion-src-placeholder").is_dir()
    assert (glue["work"] / ".src-overlay-placeholder").is_dir()
    assert not (glue["work"] / "src").exists()


# ── 3. end to end ────────────────────────────────────────────────────────

needs_real = pytest.mark.skipif(
    not (NOO_DEBUG.is_file() and shutil.which("docker")
         and subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0),
    reason="needs the debug noo (cargo build in noo-cli) and docker compose",
)

SCRATCH_COMPOSE = """\
name: bindsrc-e2e
services:
  grafana:
    image: alpine
    volumes:
      - ./pki/sso/grafana.pub:/app/pki/sso/grafana.pub:ro
      - ./configs:/etc/grafana/provisioning
      - grafana-data:/var/lib/grafana
volumes:
  grafana-data: {}
"""


def _e2e(work: Path):
    script = f"""
source {LIB_CONFIG}
source {LIB_BIND}
COMPOSE_FILES="-f docker-compose.yml"; PROFILE_ARGS=""
rc=0; check_bind_sources || rc=$?
echo "RC=$rc"
"""
    env = {**os.environ, "NOO_CLI_BIN": str(NOO_DEBUG), "NOO_DATA_ROOT": str(work / "data")}
    return subprocess.run(["bash", "-c", script], cwd=work, env=env,
                          capture_output=True, text=True, timeout=60)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(SCRATCH_COMPOSE)
    (tmp_path / "pki" / "sso").mkdir(parents=True)
    (tmp_path / "configs").mkdir()
    (tmp_path / "pki" / "sso" / "grafana.pub").write_text("key")
    return tmp_path


@needs_real
def test_e2e_all_present_passes_and_named_volume_is_ignored(project):
    out = _e2e(project)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
    assert "REFUSED" not in out.stderr and "WARNING" not in out.stderr, out.stderr


@needs_real
def test_e2e_missing_file_source_is_refused_naming_it(project):
    pub = project / "pki" / "sso" / "grafana.pub"
    pub.unlink()
    out = _e2e(project)
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert f"grafana: /app/pki/sso/grafana.pub <- {pub}: missing" in out.stderr, out.stderr
    assert "fix: noo security pki issue-sso-key" in out.stderr
    assert not pub.exists(), "the check must not create anything"


@needs_real
def test_e2e_dir_where_file_expected_is_refused_with_rmdir(project):
    pub = project / "pki" / "sso" / "grafana.pub"
    pub.unlink()
    pub.mkdir()
    out = _e2e(project)
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "EMPTY DIRECTORY where a file is expected" in out.stderr, out.stderr
    assert f"fix: sudo rmdir '{pub}', then noo security pki issue-sso-key" in out.stderr


# ── the roll-order half of the v0.2.78 outage ──────────────
#
# The compose stopped handing nats NATS_USER/NATS_PASSWORD while the
# users.conf on disk — rendered by an older CLI — still named them, and NATS
# refused the file. The launcher's pre-`up` check must refuse that start,
# naming the render, and pass once the file is re-rendered.

NATS_COMPOSE = """\
name: natsusers-e2e
services:
  nats:
    image: alpine
    volumes:
      - ./monitoring/nats/users.conf:/etc/nats/users.conf:ro
"""

RENDERED = """\
accounts {
  NOO: {
    jetstream: enabled
    users: [
      {
        user: "worker"
        password: "$2b$11$abcdefghijklmnopqrstuvabcdefghijklmnopqrstuvwxyz01234"
      }
    ]
  }
}
"""


@needs_real
def test_e2e_a_legacy_users_conf_is_refused_before_up_until_re_rendered(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(NATS_COMPOSE)
    conf = tmp_path / "monitoring" / "nats" / "users.conf"
    conf.parent.mkdir(parents=True)
    legacy = RENDERED.replace(
        "    ]\n", "      {\n        user: $NATS_USER\n        password: $NATS_PASSWORD\n      }\n    ]\n"
    )
    conf.write_text(legacy)
    out = _e2e(tmp_path)
    assert "RC=1" in out.stdout, out.stdout + out.stderr
    assert "names $NATS_USER, which the nats service is not handed" in out.stderr, out.stderr
    assert "fix: noo cluster nats-users render" in out.stderr, out.stderr
    assert conf.read_text() == legacy, "the check must not touch the file"
    conf.write_text(RENDERED)
    out = _e2e(tmp_path)
    assert "RC=0" in out.stdout, out.stdout + out.stderr
