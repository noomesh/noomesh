# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Regression tests for the 2026-08-04 baseline-generator incident.

`scripts/generate-mesh-baseline.sh` defaulted to the LIVE postgres container
and replayed the Alembic chain into a throwaway DATABASE there. Postgres roles
are CLUSTER-GLOBAL, so migrations 033/034/038 rewrote the real noo_app /
noo_evolve / noo_trellion passwords — to the literal string committed in the
script — and crash-looped the gateway twice.

Three properties are pinned here:

  A  no schema-baseline script may default to the live container
  B  the role migrations must not rewrite an EXISTING role in schema-only mode
  C  no hardcoded placeholder password may reach a role
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
VERSIONS = REPO / "src" / "noomesh" / "db" / "migrations" / "versions"
ROLE_MIGRATIONS = ("033_app_role_split.py", "034_evolve_role.py", "038_trellion_role.py")

# Any script that replays the Alembic chain to build a reference schema. Found
# by content, not by name, so a new one is covered the day it lands.
CHAIN_REPLAY_MARKER = "migration_runner import upgrade"


def _chain_replay_scripts() -> list[Path]:
    return [
        p
        for p in sorted(SCRIPTS.glob("*.sh"))
        if CHAIN_REPLAY_MARKER in p.read_text(encoding="utf-8")
    ]


# ── A: never the live cluster by default ────────────────────────────────────


def test_there_is_at_least_one_chain_replay_script():
    # Guards the guard: if the marker stops matching, every test below turns
    # into a silent pass.
    assert _chain_replay_scripts(), (
        f"no script under scripts/ matches {CHAIN_REPLAY_MARKER!r} — the "
        "detector below is now vacuous and must be updated"
    )


@pytest.mark.parametrize("script", _chain_replay_scripts(), ids=lambda p: p.name)
def test_chain_replay_script_does_not_default_to_the_live_container(script: Path):
    body = script.read_text(encoding="utf-8")
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "PGCONTAINER:=" not in stripped, (
            f"{script.name} gives PGCONTAINER a default ({stripped!r}). "
            "Roles are cluster-global: a default target means an unlucky run "
            "rewrites live credentials. Start a disposable container instead "
            "(scripts/lib-baseline-db.sh)."
        )


@pytest.mark.parametrize("script", _chain_replay_scripts(), ids=lambda p: p.name)
def test_chain_replay_script_uses_the_disposable_db_library(script: Path):
    body = script.read_text(encoding="utf-8")
    assert "lib-baseline-db.sh" in body, (
        f"{script.name} replays the Alembic chain without sourcing "
        "scripts/lib-baseline-db.sh, so nothing stops it targeting a live "
        "cluster."
    )
    assert "NOO_DB_SCHEMA_ONLY" in body, (
        f"{script.name} replays the Alembic chain without setting "
        "NOO_DB_SCHEMA_ONLY, so migrations 033/034/038 may rewrite existing "
        "cluster-global role passwords."
    )


# ── C: no hardcoded placeholder credential ──────────────────────────────────


@pytest.mark.parametrize("script", _chain_replay_scripts(), ids=lambda p: p.name)
def test_chain_replay_script_supplies_no_literal_role_password(script: Path):
    for lineno, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for var in ("NOO_APP_DB_PASSWORD", "NOO_EVOLVE_DB_PASSWORD", "NOO_TRELLION_DB_PASSWORD"):
            if f"{var}=" in stripped and ":-" in stripped:
                pytest.fail(
                    f"{script.name}:{lineno} defaults {var} to a literal. "
                    "scripts/ syncs to the public OSS repo, so that is a "
                    "published credential. Let role_provision.py mint a "
                    "random one under NOO_DB_SCHEMA_ONLY."
                )


def test_no_script_carries_the_incident_placeholder():
    hits = [
        p.name
        for p in SCRIPTS.rglob("*")
        if p.is_file()
        and p.suffix in {".sh", ".py"}
        and "baseline-gen" in p.read_text(encoding="utf-8", errors="ignore")
    ]
    assert not hits, f"the published placeholder password is back in: {hits}"


# ── B: the migrations themselves ────────────────────────────────────────────


@pytest.mark.parametrize("name", ROLE_MIGRATIONS)
def test_role_migration_goes_through_the_guard(name: str):
    body = (VERSIONS / name).read_text(encoding="utf-8")
    assert "role_provision" in body, (
        f"{name} manages a CLUSTER-GLOBAL role without the schema-only guard."
    )
    for lineno, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("*"):
            continue
        if "ALTER ROLE" in stripped and "PASSWORD" in stripped:
            pytest.fail(
                f"{name}:{lineno} rewrites a role password directly. Route it "
                "through role_provision.ensure_login_role so a schema/baseline "
                "run cannot clobber a live credential."
            )


class _FakeResult:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _FakeConn:
    """Records statements; reports a role as existing when asked to."""

    def __init__(self, existing: bool):
        self.existing = existing
        self.statements: list[str] = []

    def exec_driver_sql(self, sql, params=None):
        self.statements.append(sql)
        if "FROM pg_roles" in sql:
            return _FakeResult(1 if self.existing else None)
        return _FakeResult(None)


ATTRS = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"


def test_schema_only_leaves_an_existing_role_untouched(monkeypatch):
    from noomesh.db.role_provision import ensure_login_role

    monkeypatch.setenv("NOO_DB_SCHEMA_ONLY", "1")
    conn = _FakeConn(existing=True)
    created = ensure_login_role(conn, "noo_app", "whatever", attributes=ATTRS)

    assert created is False
    assert not any("ALTER ROLE" in s for s in conn.statements)
    assert not any("CREATE ROLE" in s for s in conn.statements)


def test_schema_only_still_creates_a_missing_role(monkeypatch):
    """A genuine fresh install inside a disposable cluster must still work."""
    from noomesh.db.role_provision import ensure_login_role

    monkeypatch.setenv("NOO_DB_SCHEMA_ONLY", "1")
    conn = _FakeConn(existing=False)
    created = ensure_login_role(conn, "noo_app", "s3cret", attributes=ATTRS)

    assert created is True
    assert any(s.startswith("CREATE ROLE noo_app") for s in conn.statements)


def test_install_mode_still_reasserts_the_password(monkeypatch):
    """The credential self-heal on a real install must not regress."""
    from noomesh.db.role_provision import ensure_login_role

    monkeypatch.delenv("NOO_DB_SCHEMA_ONLY", raising=False)
    conn = _FakeConn(existing=True)
    ensure_login_role(conn, "noo_app", "s3cret", attributes=ATTRS)

    assert any("ALTER ROLE noo_app WITH PASSWORD" in s for s in conn.statements)


def test_role_password_is_required_on_a_real_install(monkeypatch):
    from noomesh.db.role_provision import role_password

    monkeypatch.delenv("NOO_DB_SCHEMA_ONLY", raising=False)
    monkeypatch.delenv("NOO_APP_DB_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="boom"):
        role_password("NOO_APP_DB_PASSWORD", "boom")


def test_role_password_is_random_per_run_in_schema_only_mode(monkeypatch):
    from noomesh.db.role_provision import role_password

    monkeypatch.setenv("NOO_DB_SCHEMA_ONLY", "1")
    monkeypatch.delenv("NOO_APP_DB_PASSWORD", raising=False)
    a = role_password("NOO_APP_DB_PASSWORD", "boom")
    b = role_password("NOO_APP_DB_PASSWORD", "boom")

    assert a and b and a != b, "schema-only passwords must not be predictable"


# ── A (behavioural): the live-stack detector actually refuses ───────────────

_DOCKER_STUB = r"""#!/usr/bin/env bash
# Minimal `docker` stand-in. $STUB_CONTAINER_NUMBER / $STUB_DATA_MOUNT /
# $STUB_BIG_DBS decide what the inspected container looks like.
if [ "$1" = "inspect" ]; then
    case "$*" in
        *container-number*) printf '%s\n' "${STUB_CONTAINER_NUMBER:-<no value>}"; exit 0 ;;
        *compose.project*)  printf '%s\n' "pai-assistant"; exit 0 ;;
        *var/lib/postgresql/data*) printf '%s\n' "${STUB_DATA_MOUNT:-}"; exit 0 ;;
    esac
    exit 0
fi
if [ "$1" = "exec" ]; then printf '%s\n' "${STUB_BIG_DBS:-0}"; exit 0; fi
exit 0
"""

_HARNESS = """
set -euo pipefail
. "$1"
PGSUPERUSER=noo
POSTGRES_PASSWORD=x
baseline_db_assert_disposable somecontainer
"""


def _run_detector(tmp_path: Path, **stub_env: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "docker"
    stub.write_text(_DOCKER_STUB, encoding="utf-8")
    stub.chmod(0o755)

    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", **stub_env)
    env.pop("NOO_BASELINE_ALLOW_LIVE_CLUSTER", None)
    env.update(stub_env)
    return subprocess.run(
        ["bash", "-c", _HARNESS, "bash", str(SCRIPTS / "lib-baseline-db.sh")],
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_detector_refuses_a_compose_managed_cluster(tmp_path):
    r = _run_detector(tmp_path, STUB_CONTAINER_NUMBER="1")
    assert r.returncode != 0
    assert "CLUSTER-GLOBAL" in r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_detector_refuses_a_cluster_with_persistent_data(tmp_path):
    r = _run_detector(tmp_path, STUB_DATA_MOUNT="volume:pai-assistant_postgres-data")
    assert r.returncode != 0
    assert "named volume" in r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_detector_refuses_a_cluster_holding_real_data(tmp_path):
    r = _run_detector(tmp_path, STUB_BIG_DBS="2")
    assert r.returncode != 0
    assert "real data" in r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_detector_accepts_a_throwaway_container(tmp_path):
    # A CI service container: no compose labels, no persistent mount, no data.
    r = _run_detector(tmp_path)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_detector_tolerates_an_anonymous_data_volume(tmp_path):
    """Postgres images declare VOLUME on the data dir, so EVERY throwaway
    container has one. Treating that as persistent would reject CI too."""
    anon = "0" * 64
    r = _run_detector(tmp_path, STUB_DATA_MOUNT=f"volume:{anon}")
    assert r.returncode == 0, r.stderr
