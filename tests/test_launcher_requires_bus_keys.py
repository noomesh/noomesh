# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher refuses a start with no bus key for the core worker.

The gateway MACs every ``worker.*`` principal once per audience and the worker
verifies only its own key. A stack started without ``NOO_BUS_KEY_WORKER``
boots healthy and then refuses every bus message — so the launcher refuses
first, naming ``noo upgrade --stack`` (which mints it).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-secrets.sh"


def _run(tmp_path: Path, env_extra: dict[str, str], dotenv: str = "") -> subprocess.CompletedProcess:
    (tmp_path / ".env").write_text(dotenv)
    env = {k: v for k, v in os.environ.items() if not k.startswith("NOO_BUS_KEY")}
    env.update(env_extra)
    return subprocess.run(
        ["bash", "-c", f'source "{LIB}" && require_bus_keys'],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )


ALL = {"NOO_BUS_KEY_WORKER": "w", "NOO_BUS_KEY_TRELLION": "t", "NOO_BUS_KEY_TRELLION_INTEL": "i", "NOO_BROWSER_KEY": "b"}


def test_no_worker_bus_key_refuses_the_start(tmp_path: Path) -> None:
    r = _run(tmp_path, {})
    assert r.returncode == 1, r
    assert "NOO_BUS_KEY_WORKER" in r.stderr and "noo upgrade --stack" in r.stderr, r.stderr


def test_each_missing_key_refuses_the_start(tmp_path: Path) -> None:
    """Review L1: all three, not just the worker's."""
    for gone in ALL:
        env = {k: v for k, v in ALL.items() if k != gone}
        r = _run(tmp_path, env)
        assert r.returncode == 1 and gone in r.stderr, (gone, r.stderr)


def test_all_keys_in_the_environment_or_dotenv_pass(tmp_path: Path) -> None:
    assert _run(tmp_path, ALL).returncode == 0
    dotenv = "".join(f"{k}={v}\n" for k, v in ALL.items())
    assert _run(tmp_path, {}, dotenv=dotenv).returncode == 0


def test_the_launcher_calls_it_after_loading_secrets() -> None:
    src = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    load = src.index("load_secrets ||")
    check = src.index("require_bus_keys || exit 1")
    assert load < check, "the bus-key check must run after the store is loaded"
