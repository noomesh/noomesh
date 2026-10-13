# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`NOO_BIND_MODE` has no silent default: unset is a refusal.

Until 2026-09-29 `scripts/lib-bind-addr.sh` resolved an unset mode to `all`
and exported `NOO_BIND_ADDR=0.0.0.0` — every cluster-plane port (gateway,
NATS, the node agent, the model cache) on every interface,
with nobody having said so. The wizard has written an explicit value since
2026-09-24 (`noo-cli/src/onboard/steps.rs`, `bind_mode`), so the default
only ever served installs that predate it, and served them silently.

The operator's rule is fail loud. These tests run the real function: with
no `NOO_BIND_MODE` anywhere it must return non-zero, name the three values
and `noo onboard`, and export NOTHING (an exported 0.0.0.0 would still win
over compose's own `.env` substitution). They also pin that every launcher
that sources the library runs under `set -e` or checks the return code, so
"refuse" means the start stops, not that a line scrolled past.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-bind-addr.sh"
LAUNCHERS = ("scripts/noomesh-start.sh", "scripts/noomesh-restart.sh", "scripts/noomesh-rebuild.sh")


def run(tmp_path: Path, env_file: str | None, **shell_env: str) -> subprocess.CompletedProcess[str]:
    if env_file is not None:
        (tmp_path / ".env").write_text(env_file)
    # stdout is the function's banner line (dropped); stderr is the refusal.
    script = f'cd "{tmp_path}"\n. "{LIB}"\nresolve_bind_addr >/dev/null\nrc=$?\nprintf "rc=%s addr=%s" "$rc" "${{NOO_BIND_ADDR:-<unset>}}"\n'
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", **shell_env},
    )


def test_unset_mode_refuses_and_exports_nothing(tmp_path: Path) -> None:
    out = run(tmp_path, None)
    assert out.returncode == 0, "the harness itself must run; the function's rc is captured inside"
    assert out.stdout == "rc=1 addr=<unset>", out.stdout
    err = out.stderr
    assert "NOO_BIND_MODE is not set" in err, err
    for value in ("tailnet", "local", "all"):
        assert re.search(rf"\b{value}\b", err), f"the refusal must name {value!r}: {err}"
    assert "noo onboard" in err, err
    assert "0.0.0.0" in err, "say what the old default did, so the operator knows what they are choosing"


def test_an_env_file_without_the_mode_still_refuses(tmp_path: Path) -> None:
    """A .env that predates the knob (other keys, no NOO_BIND_MODE) is the
    exact install the silent default used to serve."""
    out = run(tmp_path, "NOO_DATA_ROOT=/opt/noo\n# NOO_BIND_MODE=tailnet\n")
    assert out.stdout == "rc=1 addr=<unset>", out.stdout + out.stderr


@pytest.mark.parametrize(
    ("env_file", "shell", "expect"),
    [
        ("NOO_BIND_MODE=local\n", {}, "127.0.0.1"),
        ("NOO_BIND_MODE=all\n", {}, "0.0.0.0"),
        (None, {"NOO_BIND_MODE": "local"}, "127.0.0.1"),
        (None, {"NOO_BIND_MODE": "192.0.2.7"}, "192.0.2.7"),
    ],
)
def test_a_written_mode_resolves(tmp_path: Path, env_file: str | None, shell: dict[str, str], expect: str) -> None:
    out = run(tmp_path, env_file, **shell)
    assert out.stdout == f"rc=0 addr={expect}", out.stdout + out.stderr
    assert "NOO_BIND_MODE is not set" not in out.stderr


def test_an_explicit_address_is_still_the_escape_hatch(tmp_path: Path) -> None:
    """`NOO_BIND_ADDR=<ip>` says exactly what to bind; it needs no mode."""
    out = run(tmp_path, "NOO_BIND_ADDR=192.0.2.5\n")
    assert out.stdout == "rc=0 addr=192.0.2.5", out.stdout + out.stderr


def test_the_library_has_no_all_default_left() -> None:
    """The refusal is only as good as the absence of a fallback: no
    `${NOO_BIND_MODE:-...}` expansion with a default may remain."""
    code = "\n".join(ln for ln in LIB.read_text().splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"\$\{NOO_BIND_MODE:-[^}]+\}", code), "a default for NOO_BIND_MODE is back"
    assert 'return 1' in code


@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_every_launcher_stops_on_the_refusal(launcher: str) -> None:
    """A `return 1` that the caller ignores is a warning wearing a refusal's
    clothes: compose would then start with NOO_BIND_ADDR unset and its own
    `0.0.0.0` default. Each launcher either runs under `set -e` (a failing
    plain command aborts the script) or checks the call explicitly."""
    text = (ROOT / launcher).read_text()
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "resolve_bind_addr" in code, f"{launcher} no longer resolves the bind — is the port published at all?"
    errexit = re.search(r"^\s*set\s+-[a-zA-Z]*e", code, re.M) is not None
    checked = re.search(r"resolve_bind_addr\s*\|\|", code) is not None
    assert errexit or checked, f"{launcher} calls resolve_bind_addr but neither runs under set -e nor checks its rc"
