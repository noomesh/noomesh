# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher refuses a start with no audit key, and names the fix.

The gateway refuses to boot without ``NOO_AUDIT_HMAC_KEY`` (every audit row
would be refused). The launcher says so first, in one explained line, instead
of leaving a container that exits 2 in a restart loop.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-secrets.sh"


def _run(tmp_path: Path, env_extra: dict[str, str], dotenv: str = "") -> subprocess.CompletedProcess:
    (tmp_path / ".env").write_text(dotenv)
    env = {k: v for k, v in os.environ.items() if k != "NOO_AUDIT_HMAC_KEY"}
    env.update(env_extra)
    return subprocess.run(
        ["bash", "-c", f'source "{LIB}" && require_audit_key'],
        cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
    )


def test_no_audit_key_refuses_the_start(tmp_path: Path) -> None:
    r = _run(tmp_path, {})
    assert r.returncode == 1, r
    assert "NOO_AUDIT_HMAC_KEY" in r.stderr and "noo upgrade --stack" in r.stderr, r.stderr


def test_a_blank_key_refuses_the_start(tmp_path: Path) -> None:
    assert _run(tmp_path, {}, dotenv="NOO_AUDIT_HMAC_KEY=\n").returncode == 1
    assert _run(tmp_path, {"NOO_AUDIT_HMAC_KEY": ""}).returncode == 1


def test_a_key_in_the_environment_or_dotenv_passes(tmp_path: Path) -> None:
    assert _run(tmp_path, {"NOO_AUDIT_HMAC_KEY": "k"}).returncode == 0
    assert _run(tmp_path, {}, dotenv="NOO_AUDIT_HMAC_KEY=k\n").returncode == 0


def test_the_launcher_calls_it_after_loading_secrets() -> None:
    src = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    assert src.index("load_secrets ||") < src.index("require_audit_key || exit 1")


def test_the_gateway_refuses_to_boot_without_the_key() -> None:
    main = (ROOT / "gateway-rust" / "src" / "main.rs").read_text()
    assert "audit_integrity::boot_refusal()" in main
    assert "std::process::exit(2)" in main[main.index("audit_integrity::boot_refusal()"):][:300]
