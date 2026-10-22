# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The endpoint block says where Postgres is really published.

2026-10-21: after a roll the block printed the GATEWAY's bind note right
under the PostgreSQL line ("bound to 100.x, not loopback ... Postgres is
loopback-only"), which read as Postgres being on the tailnet. The line now
derives from the same POSTGRES_BIND the compose publish uses.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _postgres_line(bind: str) -> str:
    env = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")}
    if bind:
        env["POSTGRES_BIND"] = bind
    out = subprocess.run(
        ["bash", "-c", "source scripts/lib-bind-addr.sh >/dev/null 2>&1; print_service_urls 2>&1"],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False,
    ).stdout
    lines = [l for l in out.splitlines() if "PostgreSQL" in l]
    assert lines, f"no PostgreSQL line printed:\n{out}"
    return lines[0]


def test_default_publish_reads_loopback_only() -> None:
    line = _postgres_line("")
    assert "localhost:5433" in line and "loopback only" in line


def test_a_standby_bind_is_printed_as_reachable() -> None:
    line = _postgres_line("100.64.0.9")
    assert "100.64.0.9:5433" in line and "POSTGRES_BIND" in line
    assert "loopback only" not in line


def test_the_gateway_note_no_longer_claims_postgres() -> None:
    src = (ROOT / "scripts/lib-bind-addr.sh").read_text()
    assert "Postgres are loopback-only by design" not in src
