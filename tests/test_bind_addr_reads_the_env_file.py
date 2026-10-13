# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`NOO_BIND_ADDR` / `NOO_BIND_MODE` in `.env` must actually bind.

Found 2026-09-18. The security docs of the time told operators to "set
`NOO_BIND_ADDR` to the tailnet IP to confine it". That did nothing, and did
it silently:

* the launchers never `source .env` — `scripts/lib-secrets.sh` says so in a
  comment — and `resolve_bind_addr` runs at `noomesh-start.sh:487`, four
  lines BEFORE `load_secrets`;
* so the function saw no `NOO_BIND_ADDR`, fell through to its
  `NOO_BIND_MODE:-all` default, and **exported** `NOO_BIND_ADDR=0.0.0.0`;
* an exported shell variable beats compose's own `.env` substitution
  (measured: `.env` alone → `host_ip 10.9.9.9`; exported `0.0.0.0` with the
  same `.env` → `host_ip 0.0.0.0`).

The operator followed the documentation, the port stayed on every interface,
and nothing said otherwise. These tests run the real function against a real
`.env`, because the bug lived exactly in the gap between what the file said
and what the process saw.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

LIB = Path(__file__).resolve().parents[1] / "scripts" / "lib-bind-addr.sh"


def resolve(tmp_path: Path, env_file: str | None, **shell_env: str) -> str:
    """Source the library in `tmp_path` and echo what it resolved to."""
    if env_file is not None:
        (tmp_path / ".env").write_text(env_file)
    script = f'cd "{tmp_path}"\n. "{LIB}"\nresolve_bind_addr >/dev/null 2>&1\nprintf "%s" "$NOO_BIND_ADDR"\n'
    out = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", **shell_env},  # a PATH in shell_env wins
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def no_tailnet(tmp_path: Path) -> str:
    """A PATH whose `tailscale` and `ip` find nothing, so the resolver's
    auto-detection is deterministic: the CI runners ARE tailnet members, and
    without this the "no tailnet IP" cases would resolve to the runner's own
    address and pass or fail by where the test happened to run."""
    fake = tmp_path / "fakebin"
    fake.mkdir()
    for name in ("tailscale", "ip"):
        p = fake / name
        p.write_text("#!/bin/sh\nexit 0\n")
        p.chmod(0o755)
    return f"{fake}:/usr/bin:/bin"


def test_mode_local_binds_loopback_only(tmp_path: Path) -> None:
    """The wizard's answer for a single box with no tailnet (2026-09-24):
    nothing is published beyond this machine, the model cache included."""
    assert resolve(tmp_path, "NOO_BIND_MODE=local\n") == "127.0.0.1"


def test_mode_tailnet_without_a_tailnet_ip_fails_closed(tmp_path: Path) -> None:
    """`tailnet` with tailscale down used to bind 0.0.0.0 — every port on
    every interface, the opposite of what was asked — and say so only on
    stderr. Now it binds loopback until the tailnet is back."""
    got = resolve(tmp_path, "NOO_BIND_MODE=tailnet\n", PATH=no_tailnet(tmp_path))
    assert got == "127.0.0.1"


def test_an_address_in_the_env_file_is_honoured(tmp_path: Path) -> None:
    """The documented remedy. Before this fix it returned 0.0.0.0."""
    assert resolve(tmp_path, "NOO_BIND_ADDR=192.0.2.5\n") == "192.0.2.5"


def test_a_literal_mode_in_the_env_file_is_honoured(tmp_path: Path) -> None:
    assert resolve(tmp_path, "NOO_BIND_MODE=192.0.2.7\n") == "192.0.2.7"


def test_mode_all_in_the_env_file_still_means_every_interface(tmp_path: Path) -> None:
    """Reading .env must not smuggle in a behaviour change: an operator who
    wrote `all` gets `all`."""
    assert resolve(tmp_path, "NOO_BIND_MODE=all\n") == "0.0.0.0"


def test_the_shell_environment_still_wins_over_the_file(tmp_path: Path) -> None:
    """`.env` is the persisted answer; an explicit variable is a one-off
    override and must keep beating it."""
    got = resolve(tmp_path, "NOO_BIND_ADDR=192.0.2.5\n", NOO_BIND_ADDR="192.0.2.9")
    assert got == "192.0.2.9"


def test_no_env_file_with_the_mode_in_the_environment(tmp_path: Path) -> None:
    """No .env at all is fine when the shell says what to bind. (No .env
    AND no variable is a refusal since 2026-09-29 —
    `tests/test_bind_mode_required.py`; there is no silent default left.)"""
    assert resolve(tmp_path, None, NOO_BIND_MODE="all") == "0.0.0.0"


def test_a_commented_out_line_is_not_a_value(tmp_path: Path) -> None:
    """`# NOO_BIND_ADDR=...` is an illustration, not a setting. Matching it
    would bind to a commented example — the failure reading as a success
    again, in the other direction."""
    assert resolve(tmp_path, "# NOO_BIND_ADDR=192.0.2.5\nNOO_BIND_MODE=all\n") == "0.0.0.0"


@pytest.mark.parametrize("raw", ['NOO_BIND_ADDR="192.0.2.5"\n', "NOO_BIND_ADDR = 192.0.2.5\n"])
def test_quotes_and_spacing_are_tolerated(tmp_path: Path, raw: str) -> None:
    """Hand-edited .env files carry both shapes; the launcher's other .env
    readers strip them, so this one must too."""
    assert resolve(tmp_path, raw) == "192.0.2.5"
