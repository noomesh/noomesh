# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A heartbeat action's file output stays inside its workspace (the Python half of confine.rs)."""
import os

import pytest

from noomesh.gateway.heartbeat import confined_output_path


def test_plain_relative_name_lands_in_the_workspace(tmp_path):
    ws = tmp_path / "ws"
    p = confined_output_path(str(ws), None, "activity/x.md")
    assert p == ws.resolve() / "activity" / "x.md" and p.parent.is_dir()
    assert confined_output_path(str(ws), "sub", "y.md").parent == ws.resolve() / "sub"


def test_absolute_filename_is_refused(tmp_path):
    victim = tmp_path / "noomesh.yaml"
    victim.write_text("precious")
    for f in (str(victim), "/app/noomesh.yaml", "/etc/passwd"):
        with pytest.raises(ValueError):
            confined_output_path(str(tmp_path / "ws"), None, f)
    assert victim.read_text() == "precious"


def test_dotdot_is_refused(tmp_path):
    for f in ("../escape.md", "a/../../escape.md", "a/../b.md"):
        with pytest.raises(ValueError):
            confined_output_path(str(tmp_path / "ws"), None, f)
    with pytest.raises(ValueError):
        confined_output_path(str(tmp_path / "ws"), "../other", "x.md")
    assert not (tmp_path / "escape.md").exists()


def test_override_must_be_inside_the_default_workspace(tmp_path):
    ws = tmp_path / "ws"
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ValueError):
        confined_output_path(str(ws), str(outside), "x.md")
    with pytest.raises(ValueError):
        confined_output_path(str(ws), "/app", "x.md")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlink_cannot_carry_the_write_out(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(outside, ws / "link")
    for args in ((None, "link/x.md"), (None, "link/new/x.md"), ("link", "x.md")):
        with pytest.raises(ValueError):
            confined_output_path(str(ws), *args)
    assert not (outside / "new").exists()
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.symlink(victim, ws / "log.md")
    with pytest.raises(ValueError):
        confined_output_path(str(ws), None, "log.md")
    assert victim.read_text() == "precious"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_the_open_itself_refuses_a_symlink_swapped_in_after_the_check(tmp_path):
    from noomesh.gateway.heartbeat import open_confined

    ws = tmp_path / "ws"
    p = confined_output_path(str(ws), None, "log.md")  # checked: nothing there yet
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    os.symlink(victim, p)  # swapped in between the check and the write
    with pytest.raises(OSError):
        open_confined(p)
    assert victim.read_text() == "precious"


def test_prefix_lookalikes_are_not_the_workspace(tmp_path):
    for f in ("/database/x.md", "/tmpx/x.md", "/data/../etc/x"):
        with pytest.raises(ValueError):
            confined_output_path(str(tmp_path / "ws"), None, f)


def test_route_output_and_pipelines_use_the_confinement():
    import re
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "src/noomesh/gateway/heartbeat.py").read_text()
    route = src[src.index("async def _route_output") : src.index("async def _notify")]
    assert "confined_output_path(" in route and "startswith" not in route
    assert "allowed_prefixes" not in route
    steps = src[src.index("async def _run_pipeline_steps") : src.index("temp_task = HeartbeatTask(")]
    assert "_LLM_ACTIONS" in steps, "a pipeline step may not run an agent action"


def test_opening_early_does_not_truncate_until_write_time(tmp_path):
    from noomesh.gateway.heartbeat import open_confined

    p = confined_output_path(str(tmp_path / "ws"), None, "log.md")
    p.write_text("yesterday's log")
    f = open_confined(p)  # opened before a slow gather
    f.close()  # the gather failed
    assert p.read_text() == "yesterday's log", "a failed run must not leave the file empty"
    with open_confined(p) as f:
        f.truncate(0)
        f.write("today")
    assert p.read_text() == "today"
