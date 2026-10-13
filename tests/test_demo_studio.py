# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The film studio (scripts/demo/studio.sh) and the recorder's failed-step check.

vhs is not available in CI, so these run the tape's own shell lines in a real
interactive bash and check what they record, and pin the safety properties of
the scripts that cannot be exercised without Docker."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[1] / "scripts/demo"
BASH = shutil.which("bash") or "bash"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not installed")


def typed_lines(tape: str) -> list[str]:
    """The text of every `Type ... Enter` line in a tape, backtick-quoted ones unwrapped."""
    out = []
    for line in (DEMO / tape).read_text().splitlines():
        m = re.match(r"^Type `(.*)` Enter$", line)
        if m:
            out.append(m.group(1))
    return out


def fill(s: str, tmp: Path) -> str:
    return (
        s.replace("@RAW_LOG@", str(tmp / "raw.log"))
        .replace("@MASKED_LOG@", str(tmp / "masked.log"))
        .replace("@EXIT_LOG@", str(tmp / "exit.log"))
        .replace("@MASK@", "cat")
    )


def run_film_shell(tmp: Path, commands: list[str]) -> list[str]:
    """Type the tape's setup lines, then `commands`, into an interactive bash; return the exit log lines."""
    setup = [fill(s, tmp) for s in typed_lines("onboarding.tape.in") if s.startswith(("PROMPT_COMMAND=", "noo()", "sh()"))]
    assert len(setup) == 3, "the tape must define PROMPT_COMMAND, noo() and sh()"
    fake = tmp / "bin"
    fake.mkdir()
    (fake / "noo").write_text('#!/bin/sh\necho "noo says hi"\nfor a in "$@"; do [ "$a" != "--fail" ] || { echo "boom" >&2; exit 7; }; done\n')
    (fake / "noo").chmod(0o755)
    script = "\n".join(setup + commands + ["exit"]) + "\n"
    subprocess.run(
        [BASH, "--norc", "-i"], input=script, text=True, capture_output=True, check=False,
        env={"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(tmp), "TERM": "dumb"},
    )
    log = tmp / "exit.log"
    return log.read_text().splitlines() if log.exists() else []


@needs_bash
def test_a_failing_step_leaves_a_non_zero_status_in_the_exit_log(tmp_path):
    lines = run_film_shell(tmp_path, ["noo --ok", "noo --fail", "echo fine"])
    flat = " ".join(lines).split()
    assert flat, "nothing was recorded"
    assert "7" in flat, f"the failing noo (exit 7) must be recorded, got {lines}"


@needs_bash
def test_all_steps_succeeding_records_only_zeros(tmp_path):
    lines = run_film_shell(tmp_path, ["noo --ok", "# a comment", "echo fine"])
    flat = " ".join(lines).split()
    assert flat and set(flat) == {"0"}, lines


@needs_bash
def test_a_failed_download_in_a_pipe_into_sh_is_recorded(tmp_path):
    # `curl -fsSL URL | sh`: curl fails, sh runs on empty input and succeeds; the pipeline's first status must still show.
    lines = run_film_shell(tmp_path, ["false | sh"])
    assert any(tok != "0" for tok in " ".join(lines).split()), lines


def test_every_placeholder_in_the_tapes_is_filled_by_the_recorder():
    rec = (DEMO / "record-onboarding.sh").read_text()
    for tape in ("onboarding.tape.in", "smoke.tape.in"):
        for ph in set(re.findall(r"@[A-Z_]+@", (DEMO / tape).read_text())):
            assert f"@{ph.strip('@')}@" in rec, f"{tape}: {ph} is not substituted by record-onboarding.sh"


def test_box_mode_only_trusts_containers_the_studio_made():
    rec = (DEMO / "record-onboarding.sh").read_text()
    studio = (DEMO / "studio.sh").read_text()
    assert "noo-demo-box" in rec and "noo-demo-box=1" in studio
    # every destructive studio verb checks the label before touching the container
    for verb in ("cmd_record", "cmd_down", "cmd_shell"):
        body = studio.split(f"{verb}()", 1)[1].split("\n}\n", 1)[0]
        assert "box_is_ours" in body, f"{verb} must check the label"


@needs_bash
def test_the_scripts_parse_and_help_works():
    for s in ("studio.sh", "record-onboarding.sh"):
        subprocess.run([BASH, "-n", str(DEMO / s)], check=True)
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "studio.sh up" in r.stdout


@needs_bash
def test_an_unknown_studio_command_fails_without_touching_docker():
    r = subprocess.run([BASH, str(DEMO / "studio.sh"), "frobnicate"], capture_output=True, text=True,
                       env={"PATH": "/nonexistent", "HOME": "/nonexistent"})
    assert r.returncode == 1 and "unknown command" in r.stderr
