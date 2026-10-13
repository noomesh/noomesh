# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher's `noo` failure modes — the ones review caught in PR #551
that no test exercised.

Two defects were found only in review of PR #551, never by a test:

  (1) An older `noo` on PATH (or pointed to by NOO_CLI_BIN) that is
      PRESENT but does not understand `config launch-render` (an
      unrecognized-subcommand failure, exit nonzero) made the launcher
      load NOTHING — not the python3 fallback, not the noo output, just
      silence — because the shell only checked "did `noo_bin` resolve a
      path", not "did the actual `config launch-render` call succeed".
      An absent `noo` correctly fell through to python3; a PRESENT-BUT-
      FAILING one did not.

  (2) The Rust reader's own file resolution (`launch_render::run`, when
      called with no file argument) reads `<repo_root()>/noomesh.yaml`,
      and `repo_root()` can be the STANDALONE STATE HOME (`~/.noo` or
      `$NOO_HOME`) rather than the directory the launcher script is
      actually running in. Every shell call site passes the file it
      itself resolved (`$cfg` in `lib-config.sh`, the literal
      `noomesh.yaml` in `lib-addons.sh`/the override regen, both of which
      are the launcher's OWN cwd-relative read) as an explicit argument —
      but a caller that silently dropped that argument would have `noo`
      silently resolve a DIFFERENT file than the one being started,
      without any error at all.

This file proves both are actually fixed, for all three call sites
(`load_config` in lib-config.sh, the addon map in lib-addons.sh, and
`regen_compose_override` in lib-config.sh — moved there from
noomesh-start.sh by this same change so it can be called without sourcing
the whole launcher script), and that every "external call to noo" here
behaves correctly across the three states that matter: ABSENT, PRESENT
BUT FAILING (old binary), and PRESENT AND SUCCEEDING.

Test harness note — PATH isolation: rather than assembling a directory of
symlinks to every coreutil bash happens to invoke (fragile: a script edit
that starts using a new one silently reintroduces the real environment),
every subprocess here runs with PATH="<tmp_bin>:/usr/bin:/bin" — a fixed,
minimal, always-present set that has bash/python3/grep/cut/tr/mv/rm/cat
on any Linux CI image and excludes user-local bin dirs (this machine has
a REAL `noo` at ~/.local/bin/noo, which must never leak into a case
claiming `noo` is absent). `<tmp_bin>` is empty for the ABSENT cases and
holds nothing for the PRESENT cases either — the "present" cases point
NOO_CLI_BIN directly at a fake noo script per `noo_bin()`'s own
documented precedence (`NOO_CLI_BIN` first, `command -v noo` second), so
the fake never needs to live on PATH at all.
"""

from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB_CONFIG = SCRIPTS / "lib-config.sh"
LIB_ADDONS = SCRIPTS / "lib-addons.sh"

MINIMAL_PATH = "/usr/bin:/bin"


def _minimal_env(tmp_bin: Path, extra: dict | None = None) -> dict:
    env = {
        "PATH": f"{tmp_bin}:{MINIMAL_PATH}",
        "HOME": str(tmp_bin.parent / "home"),
        "TERM": "dumb",
    }
    Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
    if extra:
        env.update(extra)
    return env


def _write_fake_noo(path: Path, mode: str) -> None:
    """A fake `noo` whose behaviour is chosen at RUN time by
    FAKE_NOO_MODE, so one script file covers fail/sentinel/record —
    fewer near-identical files to keep in sync.

    fail     — prints an "unknown command" style error and exits 2, the
               shape an older noo without `config launch-render` takes.
    sentinel — ignores its arguments and prints FAKE_NOO_SENTINEL, proving
               (when the test observes the sentinel) that noo — not the
               python3 fallback — produced the output.
    record   — appends its full argv to FAKE_NOO_RECORD_FILE and prints
               minimal valid output for whichever section was asked for,
               so the caller's success path is taken (no fallback masks
               what was recorded).
    """
    path.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            case "${FAKE_NOO_MODE:-fail}" in
              fail)
                echo "x Unknown command \\`config launch-render\\`" >&2
                exit 2
                ;;
              sentinel)
                printf '%s' "$FAKE_NOO_SENTINEL"
                exit 0
                ;;
              record)
                printf '%s\\n' "$*" >> "$FAKE_NOO_RECORD_FILE"
                case "$3" in
                  override) printf 'services: {}\\n' ;;
                  *) : ;;
                esac
                exit 0
                ;;
              *)
                echo "unknown FAKE_NOO_MODE: $FAKE_NOO_MODE" >&2
                exit 1
                ;;
            esac
            """
        )
    )
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run(script: str, cwd: Path, env: dict, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout,
    )


# ── load_config (compose_env) ───────────────────────────────────────────

LOAD_CONFIG_DRIVER = f"""
set -u
source {LIB_CONFIG}
load_config
echo "NODE_ID=${{NODE_ID:-<unset>}}"
"""


@pytest.fixture
def repo_a(tmp_path):
    d = tmp_path / "repo_a"
    d.mkdir()
    (d / "noomesh.yaml").write_text("compose_env:\n  NODE_ID: repo-a-node\n")
    return d


def test_load_config_noo_absent_uses_python_fallback(tmp_path, repo_a):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    env = _minimal_env(tmp_bin)  # no NOO_CLI_BIN, no noo on PATH
    out = _run(LOAD_CONFIG_DRIVER, repo_a, env)
    assert "NODE_ID=repo-a-node" in out.stdout, out.stdout + out.stderr


def test_load_config_noo_present_but_fails_uses_python_fallback_not_empty(tmp_path, repo_a):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "fail")
    env = _minimal_env(tmp_bin, {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "fail"})
    out = _run(LOAD_CONFIG_DRIVER, repo_a, env)
    assert "NODE_ID=repo-a-node" in out.stdout, out.stdout + out.stderr
    assert "NODE_ID=<unset>" not in out.stdout


def test_load_config_noo_present_and_succeeds_is_primary(tmp_path, repo_a):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "sentinel")
    env = _minimal_env(
        tmp_bin,
        {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "sentinel", "FAKE_NOO_SENTINEL": "SENTINEL_KEY=from_noo\n"},
    )
    out = _run(LOAD_CONFIG_DRIVER, repo_a, env)
    assert "SENTINEL_KEY" in out.stdout or True  # SENTINEL_KEY is not read back by the driver;
    # load_config exports whatever noo prints — assert the export happened,
    # proving noo (not python, which would have produced NODE_ID) was used.
    export_check = _run(
        LOAD_CONFIG_DRIVER + '\necho "SENTINEL_KEY=${SENTINEL_KEY:-<unset>}"',
        repo_a,
        env,
    )
    assert "SENTINEL_KEY=from_noo" in export_check.stdout, export_check.stdout + export_check.stderr
    # And NODE_ID (which only the python fallback would have produced from
    # this fixture's yaml) must NOT be set — noo's sentinel output replaced
    # it entirely, proving noo is primary, not merely consulted.
    assert "NODE_ID=<unset>" in export_check.stdout, export_check.stdout


def test_load_config_noo_records_the_file_the_script_reads(tmp_path, repo_a):
    """(2) above: the recorded argv must name repo_a's noomesh.yaml, even
    when NOO_REPO_ROOT points somewhere else entirely with a DIFFERENT
    noomesh.yaml — proving the shell never lets noo fall back to its own
    internal repo_root() resolution."""
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "record")
    record_file = tmp_path / "argv.log"

    repo_b = tmp_path / "repo_b_different_root"
    repo_b.mkdir()
    (repo_b / "noomesh.yaml").write_text("compose_env:\n  NODE_ID: repo-b-node\n")

    env = _minimal_env(
        tmp_bin,
        {
            "NOO_CLI_BIN": str(fake),
            "FAKE_NOO_MODE": "record",
            "FAKE_NOO_RECORD_FILE": str(record_file),
            "NOO_REPO_ROOT": str(repo_b),
        },
    )
    _run(LOAD_CONFIG_DRIVER, repo_a, env)
    assert record_file.exists(), "fake noo was never invoked"
    argv_line = record_file.read_text().strip()
    parts = argv_line.split()
    assert parts[:3] == ["config", "launch-render", "compose-env"], argv_line
    assert len(parts) >= 4, f"no file argument recorded: {argv_line!r}"
    recorded_arg = parts[3]
    recorded_path = (repo_a / recorded_arg) if not os.path.isabs(recorded_arg) else Path(recorded_arg)
    assert recorded_path.resolve() == (repo_a / "noomesh.yaml").resolve(), (
        f"recorded file arg {recorded_arg!r} does not resolve to repo_a's "
        f"noomesh.yaml (resolved: {recorded_path})"
    )
    assert "repo-a-node" in recorded_path.read_text()
    assert "repo-b-node" not in recorded_path.read_text()


def test_load_config_noo_records_explicit_NOO_CONFIG_FILE(tmp_path, repo_a):
    """With $NOO_CONFIG_FILE set, `_config_file()` resolves to THAT path —
    the recorded noo argv must be exactly that file, not the cwd default."""
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "record")
    record_file = tmp_path / "argv.log"

    other_cfg_dir = tmp_path / "elsewhere"
    other_cfg_dir.mkdir()
    other_cfg = other_cfg_dir / "custom.yaml"
    other_cfg.write_text("compose_env:\n  NODE_ID: elsewhere-node\n")

    empty_cwd = tmp_path / "empty_cwd"
    empty_cwd.mkdir()

    env = _minimal_env(
        tmp_bin,
        {
            "NOO_CLI_BIN": str(fake),
            "FAKE_NOO_MODE": "record",
            "FAKE_NOO_RECORD_FILE": str(record_file),
            "NOO_CONFIG_FILE": str(other_cfg),
        },
    )
    _run(LOAD_CONFIG_DRIVER, empty_cwd, env)
    assert record_file.exists(), "fake noo was never invoked"
    argv_line = record_file.read_text().strip()
    parts = argv_line.split()
    assert len(parts) >= 4, f"no file argument recorded: {argv_line!r}"
    assert Path(parts[3]).resolve() == other_cfg.resolve(), parts[3]


# ── lib-addons.sh (NOO_ADDON_MAP) ───────────────────────────────────────

ADDONS_DRIVER = f"""
set -u
source {LIB_CONFIG}
source {LIB_ADDONS}
echo "MAP=[${{NOO_ADDON_MAP}}]"
"""


@pytest.fixture
def repo_addons(tmp_path):
    d = tmp_path / "repo_addons"
    d.mkdir()
    (d / "noomesh.yaml").write_text("addons:\n  trellion: true\n  voice: false\n")
    return d


def test_addons_noo_absent_uses_python_fallback(tmp_path, repo_addons):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    env = _minimal_env(tmp_bin)
    out = _run(ADDONS_DRIVER, repo_addons, env)
    assert "trellion=1" in out.stdout, out.stdout + out.stderr
    assert "voice=0" in out.stdout, out.stdout + out.stderr


def test_addons_noo_present_but_fails_uses_python_fallback_not_empty(tmp_path, repo_addons):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "fail")
    env = _minimal_env(tmp_bin, {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "fail"})
    out = _run(ADDONS_DRIVER, repo_addons, env)
    assert "trellion=1" in out.stdout, out.stdout + out.stderr
    assert "MAP=[]" not in out.stdout, out.stdout


def test_addons_noo_present_and_succeeds_is_primary(tmp_path, repo_addons):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "sentinel")
    env = _minimal_env(
        tmp_bin,
        {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "sentinel", "FAKE_NOO_SENTINEL": "sentinel_addon=1\n"},
    )
    out = _run(ADDONS_DRIVER, repo_addons, env)
    assert "sentinel_addon=1" in out.stdout, out.stdout + out.stderr
    # python would have produced "trellion=1" from this fixture — absence
    # of it proves noo's output replaced python's, not merely ran first.
    assert "trellion=1" not in out.stdout, out.stdout


def test_addons_noo_records_the_file_the_script_reads(tmp_path, repo_addons):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "record")
    record_file = tmp_path / "argv.log"

    repo_b = tmp_path / "repo_b_different_root"
    repo_b.mkdir()
    (repo_b / "noomesh.yaml").write_text("addons:\n  trellion: false\n")

    env = _minimal_env(
        tmp_bin,
        {
            "NOO_CLI_BIN": str(fake),
            "FAKE_NOO_MODE": "record",
            "FAKE_NOO_RECORD_FILE": str(record_file),
            "NOO_REPO_ROOT": str(repo_b),
        },
    )
    _run(ADDONS_DRIVER, repo_addons, env)
    assert record_file.exists(), "fake noo was never invoked"
    parts = record_file.read_text().strip().split()
    assert parts[:3] == ["config", "launch-render", "addons"], parts
    assert len(parts) >= 4, f"no file argument recorded: {parts}"
    recorded_path = (repo_addons / parts[3]) if not os.path.isabs(parts[3]) else Path(parts[3])
    assert recorded_path.resolve() == (repo_addons / "noomesh.yaml").resolve()
    assert "trellion: true" in recorded_path.read_text()


# ── regen_compose_override ──────────────────────────────────────────────

OVERRIDE_DRIVER = f"""
set -u
source {LIB_CONFIG}
regen_compose_override
"""


@pytest.fixture
def repo_override(tmp_path):
    d = tmp_path / "repo_override"
    d.mkdir()
    (d / "noomesh.yaml").write_text(
        "workspace:\n  enabled: true\n  host: /home/op/ws\n  mount: /workspace\n"
    )
    return d


def _override_out(repo: Path) -> str:
    f = repo / "docker-compose.override.yml"
    return f.read_text() if f.exists() else "<missing>"


def test_override_noo_absent_uses_python_fallback(tmp_path, repo_override):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    env = _minimal_env(tmp_bin)
    _run(OVERRIDE_DRIVER, repo_override, env)
    out = _override_out(repo_override)
    assert "/home/op/ws:/workspace:rw" in out, out


def test_override_noo_present_but_fails_uses_python_fallback_not_stale(tmp_path, repo_override):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "fail")
    # Seed a STALE override that must be REPLACED (not just "left") by the
    # python fallback, proving the fallback actually ran rather than the
    # noo branch quietly declaring success on a failed command.
    (repo_override / "docker-compose.override.yml").write_text("services: {}\n# stale\n")
    env = _minimal_env(tmp_bin, {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "fail"})
    _run(OVERRIDE_DRIVER, repo_override, env)
    out = _override_out(repo_override)
    assert "/home/op/ws:/workspace:rw" in out, out
    assert "# stale" not in out, out


def test_override_noo_present_and_succeeds_is_primary(tmp_path, repo_override):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "sentinel")
    env = _minimal_env(
        tmp_bin,
        {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "sentinel", "FAKE_NOO_SENTINEL": "# SENTINEL OVERRIDE\nservices: {}\n"},
    )
    _run(OVERRIDE_DRIVER, repo_override, env)
    out = _override_out(repo_override)
    assert "# SENTINEL OVERRIDE" in out, out
    assert "/workspace" not in out, out


def test_override_noo_records_the_file_the_script_reads(tmp_path, repo_override):
    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "record")
    record_file = tmp_path / "argv.log"

    repo_b = tmp_path / "repo_b_different_root"
    repo_b.mkdir()
    (repo_b / "noomesh.yaml").write_text("workspace:\n  enabled: false\n")

    env = _minimal_env(
        tmp_bin,
        {
            "NOO_CLI_BIN": str(fake),
            "FAKE_NOO_MODE": "record",
            "FAKE_NOO_RECORD_FILE": str(record_file),
            "NOO_REPO_ROOT": str(repo_b),
        },
    )
    _run(OVERRIDE_DRIVER, repo_override, env)
    assert record_file.exists(), "fake noo was never invoked"
    parts = record_file.read_text().strip().split()
    assert parts[:3] == ["config", "launch-render", "override"], parts
    assert len(parts) >= 4, f"no file argument recorded: {parts}"
    recorded_path = (repo_override / parts[3]) if not os.path.isabs(parts[3]) else Path(parts[3])
    assert recorded_path.resolve() == (repo_override / "noomesh.yaml").resolve()
    assert "/home/op/ws" in recorded_path.read_text()


def test_override_noo_and_python_both_fail_leaves_file_byte_identical(tmp_path, repo_override):
    """Case e: noo fails (or is absent) AND the python3 fallback itself
    fails (a genuine YAML syntax error) — the existing
    docker-compose.override.yml must be left completely untouched, not
    truncated or partially written. This is the whole reason the real
    regen writes to a .tmp file and `mv`s it into place only on success."""
    (repo_override / "noomesh.yaml").write_text("workspace: {enabled: \n")  # syntax error
    existing = "services: {}\n# pre-existing, must survive\n"
    (repo_override / "docker-compose.override.yml").write_text(existing)

    tmp_bin = tmp_path / "bin"
    tmp_bin.mkdir()
    fake = tmp_bin / "fake-noo"
    _write_fake_noo(fake, "fail")
    env = _minimal_env(tmp_bin, {"NOO_CLI_BIN": str(fake), "FAKE_NOO_MODE": "fail"})
    result = _run(OVERRIDE_DRIVER, repo_override, env)
    out = _override_out(repo_override)
    assert out == existing, f"override file changed on double-failure:\n{out!r}"
    assert "override regen failed" in result.stderr, result.stderr
    # No leftover temp file either.
    assert not (repo_override / "docker-compose.override.yml.tmp").exists()
