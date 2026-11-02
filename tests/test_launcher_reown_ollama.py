# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The hardened Ollama image runs as 65532; the launcher re-owns the stores once.

The compose ollama services mount their store at /home/nonroot/.ollama (it was
/root/.ollama), the SAME host directory / named volume, so no model moves. The
old root image wrote the store as root: before `up` the launcher stops the
service, `chown -R 65532:65532` (never deletes or moves) and verifies, through
lib-reown.sh's throwaway-container runner (NOO_REOWN_CMD stands in for it).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

from tests.test_launcher_reown_nonroot_dirs import FAKE_RUNNER

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-reown.sh"
COMPOSE = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())["services"]


def _env(tmp: Path):
    runner = tmp / "runner.sh"
    runner.write_text(FAKE_RUNNER)
    runner.chmod(0o755)
    log = tmp / "log"
    log.write_text("")
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "docker").write_text('#!/bin/bash\n[ "$1 $2" = "volume ls" ] && echo "noomesh_ollama-embed-data"; exit 0\n')
    (bindir / "docker").chmod(0o755)
    return runner, log, bindir


def _run(tmp: Path, active: str, store: Path, extra=None):
    runner, log, bindir = _env(tmp)
    env = dict(os.environ, NOO_REOWN_CMD=str(runner), LOG=str(log), OLLAMA_DATA_DIR=str(store), PATH=f"{bindir}:{os.environ['PATH']}")
    env.update(extra or {})
    script = (f'set -e; source "{LIB}"; reown_stop_service() {{ echo "stop $1" >> "{log}"; }}; '
              f'reown_ollama_stores "{active}"')
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, cwd=tmp), log


def test_a_root_owned_ollama_store_is_reowned_once_after_a_stop(tmp_path: Path) -> None:
    store = tmp_path / "ollama"
    (store / "models").mkdir(parents=True)
    (store / ".ledger").write_text(f"{store}/models/blobs/sha256-aa\n")
    r, log = _run(tmp_path, "ollama", store)
    assert r.returncode == 0, r.stderr
    assert f"re-owned 1 path(s) under {store} to 65532" in r.stdout
    calls = log.read_text().splitlines()
    chown = [c for c in calls if c.startswith("chown")]
    assert chown == [f"chown -R 65532:65532 {store}"], calls
    assert calls.index("stop ollama") < calls.index(chown[0])
    # a second launcher run finds nothing to do: idempotent, silent, no stop
    r2, log2 = _run(tmp_path, "ollama", store)
    assert r2.returncode == 0 and r2.stdout == "", r2
    assert not any(c.startswith(("chown", "stop")) for c in log2.read_text().splitlines())


def test_never_deletes_or_moves(tmp_path: Path) -> None:
    store = tmp_path / "ollama"
    store.mkdir()
    (store / ".ledger").write_text(f"{store}/x\n")
    _, log = _run(tmp_path, "ollama", store)
    for c in log.read_text().splitlines():
        assert not c.startswith(("rm ", "mv ")), c
    assert "rm -" not in LIB.read_text().split("reown_nonroot_path()")[1].split("reown_nonroot_dirs()")[0]


def test_the_embed_volume_is_reowned_and_the_cpu_twin_stopped(tmp_path: Path) -> None:
    store = tmp_path / "ollama"
    store.mkdir()
    vol = tmp_path / "noomesh_ollama-embed-data"   # the fake runner treats the volume name as a dir under cwd
    vol.mkdir()
    (vol / ".ledger").write_text("/d/models/blobs/sha256-bb\n")
    r, log = _run(tmp_path, "ollama-embed\nollama-embed-cpu", store)
    assert r.returncode == 0, r.stderr
    calls = log.read_text().splitlines()
    assert "stop ollama-embed-cpu" in calls and "stop ollama-embed" in calls, calls
    assert "chown -R 65532:65532 noomesh_ollama-embed-data" in calls, calls
    # not active -> not touched
    r, log = _run(tmp_path, "redis", store)
    assert r.returncode == 0 and log.read_text() == ""


def test_compose_mounts_the_stores_at_the_non_root_home_and_never_sets_root() -> None:
    for name in ("ollama", "ollama-embed", "ollama-embed-cpu"):
        vols = [v for v in COMPOSE[name]["volumes"] if isinstance(v, str)]
        assert any(v.endswith(":/home/nonroot/.ollama") for v in vols), (name, vols)
        assert not any(v.endswith("/root/.ollama") for v in vols), (name, vols)
        assert str(COMPOSE[name].get("user", "65532")) not in ("0", "root", "0:0"), name
        assert COMPOSE[name].get("privileged") is not True
    start = (ROOT / "scripts/noomesh-start.sh").read_text()
    assert start.count("reown_ollama_stores") == 2, "both launcher start paths re-own before `up`"
