# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`cluster.postgres_memory: standard | auto` in the launcher (lib-config.sh).

THE RULES:
* Unset (or `standard`, or a typo) exports NOTHING, so compose's own
  `${NOO_PG_*:-default}` values apply byte for byte as before the setting.
* `auto` exports the tier for the memory Docker reports: below 6 GiB the
  4 GB row, below 12 GiB the 8 GB row, else the compose defaults.
* An explicit NOO_PG_* (environment, compose_env once load_config exported
  it, `.env`) always wins: `auto` never exports over it.
* The shell table is the Rust table (noo-cli/src/commands/postgres_memory.rs),
  which onboard and `noo cluster verify` use.

The helpers run for real under bash; the machine's memory is faked by
redefining `postgres_memory_ram_kb` after sourcing (no env switch).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-config.sh"
COMPOSE = ROOT / "docker-compose.cluster.yml"
RUST = ROOT / "noo-cli" / "src" / "commands" / "postgres_memory.rs"

KEYS = ["NOO_PG_SHARED_BUFFERS", "NOO_PG_EFFECTIVE_CACHE_SIZE", "NOO_PG_WORK_MEM",
        "NOO_PG_MAINTENANCE_WORK_MEM", "NOO_PG_SHM_SIZE"]
SMALL = ["128MB", "512MB", "8MB", "64MB", "256m"]
MEDIUM = ["256MB", "1GB", "16MB", "128MB", "512m"]
STANDARD = ["512MB", "2GB", "32MB", "256MB", "1g"]

GIB_KB = 1024 * 1024
PRINT = 'for k in ' + " ".join(KEYS) + '; do printf "%s=%s\\n" "$k" "$(printenv "$k")"; done'


def _bash(tmp_path: Path, body: str, yaml: str | None, ram_kb: int | None = 16 * GIB_KB,
          env_extra: dict | None = None, dotenv: str | None = None) -> subprocess.CompletedProcess:
    if yaml is not None:
        (tmp_path / "noomesh.yaml").write_text(yaml)
    if dotenv is not None:
        (tmp_path / ".env").write_text(dotenv)
    env = {k: v for k, v in os.environ.items()
           if k not in ("NOO_CLI_BIN", "NOO_CONTAINER_PREFIX", "COMPOSE_PROFILES") and not k.startswith("NOO_PG_")}
    # No `noo` on PATH; python3 with PyYAML first (the fallback reader).
    path = [p for p in env.get("PATH", "").split(":") if p and not (Path(p) / "noo").exists()]
    env["PATH"] = ":".join([str(Path(sys.executable).parent)] + path)
    env.update(env_extra or {})
    fake = f"postgres_memory_ram_kb() {{ printf '%s' '{'' if ram_kb is None else ram_kb}'; }}\n"
    return subprocess.run(["bash", "-c", f". {LIB}\n{fake}{body}"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)


def _derived(tmp_path: Path, yaml: str | None, **kw) -> dict[str, str]:
    r = _bash(tmp_path, f"postgres_memory_derive_env\n{PRINT}", yaml, **kw)
    assert r.returncode == 0, r
    return dict(line.split("=", 1) for line in r.stdout.splitlines())


def _values(d: dict[str, str]) -> list[str]:
    return [d[k] for k in KEYS]


def test_standard_is_what_compose_already_defaults_to():
    text = COMPOSE.read_text()
    for k, v in zip(KEYS, STANDARD):
        assert f"${{{k}:-{v}}}" in text, f"{k}'s compose default is no longer {v}"


@pytest.mark.parametrize("yaml", [
    None,
    "cluster:\n  default_backend: vllm\n",
    "cluster:\n  postgres_memory: standard\n",
    "postgres_memory: auto\n",  # only the cluster key counts
])
def test_unset_and_standard_export_nothing(tmp_path, yaml):
    assert _values(_derived(tmp_path, yaml, ram_kb=3 * GIB_KB)) == [""] * 5, \
        "standard must leave every NOO_PG_* unset, so compose's defaults apply unchanged"


def test_a_typo_is_standard_and_says_so(tmp_path):
    r = _bash(tmp_path, f"postgres_memory_derive_env\n{PRINT}", "cluster:\n  postgres_memory: Auto\n", ram_kb=3 * GIB_KB)
    assert all(line.endswith("=") for line in r.stdout.splitlines()), r.stdout
    assert "neither standard nor auto" in r.stderr


@pytest.mark.parametrize("ram_kb,want", [
    (3_900_000, SMALL),          # a 4 GB machine
    (6 * GIB_KB - 1, SMALL),
    (6 * GIB_KB, MEDIUM),
    (7_900_000, MEDIUM),         # an 8 GB machine
    (12 * GIB_KB - 1, MEDIUM),
    (12 * GIB_KB, STANDARD),
    (15_900_000, STANDARD),      # a 16 GB machine reads about 15.2 GiB
    (64 * GIB_KB, STANDARD),
])
def test_auto_picks_the_tier(tmp_path, ram_kb, want):
    assert _values(_derived(tmp_path, "cluster:\n  postgres_memory: auto\n", ram_kb=ram_kb)) == want


def test_auto_with_unknown_memory_exports_nothing(tmp_path):
    r = _bash(tmp_path, f"postgres_memory_derive_env\n{PRINT}", "cluster:\n  postgres_memory: auto\n", ram_kb=None)
    assert all(line.endswith("=") for line in r.stdout.splitlines()), r.stdout
    assert "could not be read" in r.stderr


def test_an_explicit_environment_value_wins(tmp_path):
    d = _derived(tmp_path, "cluster:\n  postgres_memory: auto\n", ram_kb=3 * GIB_KB,
                 env_extra={"NOO_PG_WORK_MEM": "64MB", "NOO_PG_SHM_SIZE": ""})
    assert d["NOO_PG_WORK_MEM"] == "64MB", "auto must never replace what the operator set"
    assert d["NOO_PG_SHM_SIZE"] == "256m", "an empty value is unset (compose's :- treats it so)"
    assert d["NOO_PG_SHARED_BUFFERS"] == "128MB"


def test_an_explicit_dotenv_value_wins(tmp_path):
    d = _derived(tmp_path, "cluster:\n  postgres_memory: auto\n", ram_kb=3 * GIB_KB,
                 dotenv="NOO_PG_SHARED_BUFFERS=1GB\nexport NOO_PG_WORK_MEM=\"48MB\"\nNOO_PG_SHM_SIZE=\n")
    # Not exported: compose reads .env itself, and the operator's value stands.
    assert d["NOO_PG_SHARED_BUFFERS"] == "" and d["NOO_PG_WORK_MEM"] == ""
    assert d["NOO_PG_SHM_SIZE"] == "256m", "an empty .env value is unset"
    assert d["NOO_PG_EFFECTIVE_CACHE_SIZE"] == "512MB"


def test_a_compose_env_value_wins(tmp_path):
    # load_config exports compose_env before derive_profile_env runs.
    yaml = "cluster:\n  postgres_memory: auto\ncompose_env:\n  NOO_PG_MAINTENANCE_WORK_MEM: 512MB\n"
    r = _bash(tmp_path, f"load_config >/dev/null 2>&1\nderive_profile_env\n{PRINT}", yaml, ram_kb=3 * GIB_KB)
    d = dict(line.split("=", 1) for line in r.stdout.splitlines())
    assert d["NOO_PG_MAINTENANCE_WORK_MEM"] == "512MB", r
    assert d["NOO_PG_WORK_MEM"] == "8MB", "derive_profile_env must run the postgres_memory derivation"


def _fake_noo(tmp_path: Path, script: str) -> str:
    noo = tmp_path / "fake-noo"
    noo.write_text("#!/bin/bash\n" + script)
    noo.chmod(0o755)
    return str(noo)


def test_the_noo_renderer_is_read_first(tmp_path):
    noo = _fake_noo(tmp_path, '[ "$1 $2 $3" = "config launch-render postgres-memory" ] && { echo auto; exit 0; }\nexit 64\n')
    d = _derived(tmp_path, "cluster:\n  postgres_memory: standard\n", ram_kb=3 * GIB_KB, env_extra={"NOO_CLI_BIN": noo})
    assert _values(d) == SMALL


def test_an_older_noo_without_the_section_falls_back_to_python(tmp_path):
    noo = _fake_noo(tmp_path, 'echo "x Unknown command" >&2\nexit 2\n')
    d = _derived(tmp_path, "cluster:\n  postgres_memory: auto\n", ram_kb=7 * GIB_KB, env_extra={"NOO_CLI_BIN": noo})
    assert _values(d) == MEDIUM


def _rust_array(name: str) -> list[str]:
    m = re.search(rf"pub\(crate\) const {name}: \[&str; 5\] = \[([^\]]*)\];", RUST.read_text())
    assert m, f"{name} not found in {RUST}"
    return re.findall(r'"([^"]*)"', m.group(1))


def test_the_shell_table_is_the_rust_table():
    src = RUST.read_text()
    assert _rust_array("KEYS") == KEYS
    assert _rust_array("SMALL") == SMALL
    assert _rust_array("MEDIUM") == MEDIUM
    assert _rust_array("STANDARD") == STANDARD
    assert "pub(crate) const SMALL_BELOW: u64 = 6 * GIB;" in src
    assert "pub(crate) const MEDIUM_BELOW: u64 = 12 * GIB;" in src
    shell = LIB.read_text()
    assert f'PG_MEMORY_KEYS="{" ".join(KEYS)}"' in shell
    for row in (SMALL, MEDIUM, STANDARD):
        assert f"printf '{' '.join(row)}'" in shell
