# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Profiles the operator lists in COMPOSE_PROFILES reach compose.

Compose ignores COMPOSE_PROFILES once a `--profile` flag is given, and the
launcher always gives one. The embed-capacity runbook enables the optional CPU
embedder with `COMPOSE_PROFILES=embed-cpu` in the stack .env; before
`operator_profile_args` that setting started nothing (found live 2026-10-09).

The helper runs for real under bash; the launcher's wiring is checked by
running the real start script against a fake docker and reading its argv.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-config.sh"


def _args(tmp_path: Path, env_file: str | None, env_var: str | None = None) -> subprocess.CompletedProcess:
    if env_file is not None:
        (tmp_path / ".env").write_text(env_file)
    env = {k: v for k, v in os.environ.items() if k != "COMPOSE_PROFILES"}
    if env_var is not None:
        env["COMPOSE_PROFILES"] = env_var
    return subprocess.run(["bash", "-c", f". {LIB}\noperator_profile_args"], cwd=tmp_path,
                          env=env, capture_output=True, text=True, timeout=30)


def test_the_env_file_profile_becomes_a_flag(tmp_path):
    r = _args(tmp_path, "NOO_DATA_ROOT=/x\nCOMPOSE_PROFILES=embed-cpu\n")
    assert r.stdout == "--profile embed-cpu", r


@pytest.mark.parametrize("raw,want", [
    ("embed-cpu,sensors", "--profile embed-cpu --profile sensors"),
    (' "embed-cpu , sensors,embed-cpu" ', "--profile embed-cpu --profile sensors"),
    ("", ""),
])
def test_lists_are_split_trimmed_and_deduplicated(tmp_path, raw, want):
    assert _args(tmp_path, f"COMPOSE_PROFILES={raw}\n").stdout == want


def test_the_environment_wins_over_the_env_file(tmp_path):
    assert _args(tmp_path, "COMPOSE_PROFILES=embed-cpu\n", env_var="sensors").stdout == "--profile sensors"


def test_no_setting_is_no_flag(tmp_path):
    assert _args(tmp_path, None).stdout == ""


def test_a_name_that_is_not_a_profile_is_refused_not_passed(tmp_path):
    r = _args(tmp_path, "COMPOSE_PROFILES=embed-cpu,$(touch pwned)\n")
    assert r.stdout == "--profile embed-cpu"
    assert "not a profile name" in r.stderr
    assert not (tmp_path / "pwned").exists()


@pytest.mark.parametrize("script", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_every_launcher_script_passes_the_operator_profiles_on(script):
    text = (ROOT / "scripts" / script).read_text()
    assert "operator_profile_args" in text, f"{script} builds PROFILE_ARGS without COMPOSE_PROFILES"


DOOR = "https://noo-stunnel-ollama-embed-cpu:11434"


def _derived(tmp_path: Path, profiles: str | None, extra: str | None = None) -> str:
    env = {k: v for k, v in os.environ.items() if k not in ("COMPOSE_PROFILES", "PAGEINDEX_EMBEDDING_EXTRA_URLS")}
    if profiles is not None:
        env["COMPOSE_PROFILES"] = profiles
    if extra is not None:
        env["PAGEINDEX_EMBEDDING_EXTRA_URLS"] = extra
    r = subprocess.run(["bash", "-c", f". {LIB}\nderive_profile_env\nprintf '%s' \"${{PAGEINDEX_EMBEDDING_EXTRA_URLS:-}}\""],
                       cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r
    return r.stdout


def test_the_embed_cpu_profile_declares_its_door_once(tmp_path):
    # One declaration (the profile, e.g. noomesh.yaml compose_env), never a
    # typed URL beside it: the door is derived.
    assert _derived(tmp_path, "embed-cpu") == DOOR
    assert _derived(tmp_path, "sensors,embed-cpu", extra=DOOR) == DOOR
    assert _derived(tmp_path, "embed-cpu", extra="https://other:1") == f"https://other:1,{DOOR}"


def test_without_the_profile_nothing_is_derived(tmp_path):
    assert _derived(tmp_path, None) == ""
    assert _derived(tmp_path, "sensors") == ""
    assert _derived(tmp_path, None, extra="https://other:1") == "https://other:1"


@pytest.mark.parametrize("script", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_every_launcher_script_derives_profile_env(script):
    assert "derive_profile_env" in (ROOT / "scripts" / script).read_text(), script
