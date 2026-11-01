# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Stopping one service must survive a reboot (i301 a.4).

boot-restore (node-agent-go/internal/hostd/boot.go) starts every stopped
core container after a reboot, and never recreates one. So
`noomesh-stop.sh <service>` removes the service's container: a plain
`compose stop` left an exited container that boot-restore started again.

The real script runs against a fake docker that records its argv, from a
scratch directory: the script clears ./secrets/.runtime, which in a live
checkout is the running stack's.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STOP = ROOT / "scripts" / "noomesh-stop.sh"


def _compose_calls(tmp_path: Path, *args: str) -> list[list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    fake = bin_dir / "docker"
    fake.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$FAKE_DOCKER_LOG"\nexit 0\n')
    fake.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", FAKE_DOCKER_LOG=str(log))
    r = subprocess.run(["bash", str(STOP), *args], cwd=tmp_path, env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    lines = log.read_text().splitlines() if log.exists() else []
    return [ln.split() for ln in lines if ln.startswith("compose ")]


def test_stopping_one_service_removes_its_container(tmp_path):
    calls = _compose_calls(tmp_path, "nats")
    assert calls, "the script never called docker compose: the fake is not on its PATH"
    last = calls[-1]
    assert last[-4:] == ["rm", "--stop", "--force", "nats"], (
        f"one-service stop must remove the container (boot-restore restarts an exited one): {last}"
    )
    assert not any(c[-2:] == ["stop", "nats"] for c in calls), f"a plain compose stop is back: {calls}"


def test_the_profile_form_removes_too(tmp_path):
    last = _compose_calls(tmp_path, "--profile", "controller", "nats")[-1]
    assert "--profile" in last and last[-4:] == ["rm", "--stop", "--force", "nats"], last
