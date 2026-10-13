# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""fu 53: a named instance must never share the default data root.

Every stateful compose volume is a device-bind under NOO_DATA_ROOT, so two
instances with one root share postgres/redis/nats FILES — the 2026-08-14
incident had a test instance replaying WAL inside production's live postgres
directory. lib-instance.sh now refuses a non-default instance whose resolved
root is not instance-scoped; these tests pin that refusal, the paths that
must keep working, and the deliberate escape hatch.

The guard is exercised by SOURCING the real script (it self-invokes
noo_instance_env), not by extracting functions — the incident shipped through
the real sourcing path, so that is the path under test.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB = REPO_ROOT / "scripts" / "lib-instance.sh"


def source_lib(tmp_path, env: dict[str, str]) -> subprocess.CompletedProcess:
    """Source lib-instance.sh in a clean dir (no .env unless the test made one)."""
    full = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    full.update(env)
    return subprocess.run(
        ["bash", "-c", f'source "{LIB}" && echo GUARD_PASSED project=$COMPOSE_PROJECT_NAME'],
        cwd=tmp_path,
        env=full,
        capture_output=True,
        text=True,
        timeout=15,
    )


class TestInstanceDataRootGuard:
    def test_named_instance_with_unscoped_root_refuses(self, tmp_path):
        r = source_lib(tmp_path, {"NOO_INSTANCE": "obtest", "NOO_DATA_ROOT": "/mnt/d/noo"})
        assert r.returncode != 0, "sharing the default root must be fatal"
        assert "GUARD_PASSED" not in r.stdout, "nothing after the guard may run"
        assert "OPEN ANOTHER INSTALL'S DATABASES" in r.stderr
        assert "instances/obtest" in r.stderr, "the message must name the fix"

    def test_named_instance_with_scoped_root_proceeds(self, tmp_path):
        r = source_lib(
            tmp_path,
            {"NOO_INSTANCE": "obtest", "NOO_DATA_ROOT": "/mnt/d/noo/instances/obtest"},
        )
        assert r.returncode == 0, r.stderr
        assert "project=noo-obtest" in r.stdout

    def test_unscoped_root_from_dotenv_also_refuses(self, tmp_path):
        # The incident's actual shape: nothing in the environment — the root
        # came from files. The guard must read .env, not only the env.
        (tmp_path / ".env").write_text("NOO_INSTANCE=obtest\nNOO_DATA_ROOT=/mnt/d/noo\n")
        r = source_lib(tmp_path, {})
        assert r.returncode != 0
        assert "OPEN ANOTHER INSTALL'S DATABASES" in r.stderr

    def test_default_root_when_nothing_set_still_refuses_for_instance(self, tmp_path):
        # No env, no .env value: the resolved root falls back to the neutral
        # default, which is exactly the deterministic collision that hit
        # production (then /mnt/d/noo) — still not instance-scoped, so refused.
        r = source_lib(tmp_path, {"NOO_INSTANCE": "obtest"})
        assert r.returncode != 0
        assert "/var/lib/noo" in r.stderr

    def test_escape_hatch_is_deliberate_and_works(self, tmp_path):
        r = source_lib(
            tmp_path,
            {
                "NOO_INSTANCE": "obtest",
                "NOO_DATA_ROOT": "/mnt/d/noo",
                "NOO_INSTANCE_UNSAFE_DATA_ROOT": "1",
            },
        )
        assert r.returncode == 0, "forensics/cleanup path must stay possible"
        assert "GUARD_PASSED" in r.stdout

    def test_default_install_is_completely_untouched(self, tmp_path):
        # The guard must never fire for the ordinary single-install machine.
        r = source_lib(tmp_path, {"NOO_DATA_ROOT": "/mnt/d/noo"})
        assert r.returncode == 0, r.stderr
        assert "FATAL" not in r.stderr
        assert "GUARD_PASSED" in r.stdout
