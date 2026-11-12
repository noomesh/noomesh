# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""test-core-local's venv cache is pruned (2026-11-10).

test-core-local.sh keys its venv on the checkout's path, so every worktree
got its own (~2 GB) and nothing removed one: awolf's root volume reached
0 MB free with 114 venvs, 192 GB. scripts/test-core-venv-prune.sh keeps the
most recently USED few, removes the rest, never the current one and never
one in use, touches nothing that is not a venv, and says what it freed.
These run the REAL script on a throwaway cache.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRUNE = ROOT / "scripts" / "test-core-venv-prune.sh"
LOCAL = ROOT / "scripts" / "test-core-local.sh"
DEAD_PID = "4194303"  # above Linux's default pid_max: never alive


def _venv(cache: Path, name: str, used: int, size: int = 1000, in_use: str | None = None) -> Path:
    v = cache / name
    (v / "bin").mkdir(parents=True)
    (v / "bin" / "blob").write_bytes(b"x" * size)
    (v / ".ci-install-stamp").write_text("stamp\n")
    (v / ".last-used").write_text("")
    os.utime(v / ".last-used", (used, used))
    if in_use:
        (v / ".in-use").mkdir()
        (v / ".in-use" / in_use).write_text("")
    return v


def _prune(cache: Path, keep: int, current: Path) -> str:
    p = subprocess.run(["bash", str(PRUNE), str(cache), str(keep), str(current)],
                       capture_output=True, text=True, check=True)
    return p.stdout


def _left(cache: Path) -> list[str]:
    return sorted(p.name for p in cache.iterdir())


def test_it_keeps_the_most_recently_used_and_says_what_it_freed(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    for i in range(10):
        _venv(cache, f"v{i}", used=1_000_000 + i * 100, size=4096)
    current = cache / "v9"
    out = _prune(cache, 3, current)
    assert _left(cache) == ["v7", "v8", "v9"], _left(cache)
    lines = out.strip().splitlines()
    assert len(lines) == 1, out
    assert "pruned 7 unused venv(s)" in lines[0] and str(cache) in lines[0] and "freed" in lines[0], lines[0]


def test_a_dry_run_lists_and_removes_nothing(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    for i in range(4):
        _venv(cache, f"v{i}", used=1_000_000 + i * 100)
    p = subprocess.run(["bash", str(PRUNE), "--dry-run", str(cache), "1", str(cache / "v3")],
                       capture_output=True, text=True, check=True)
    assert _left(cache) == ["v0", "v1", "v2", "v3"], "a dry run removes nothing"
    assert p.stdout.count("would remove ") == 3 and "would prune 3" in p.stdout, p.stdout


def test_the_current_venv_is_never_removed_even_when_oldest(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    for i in range(5):
        _venv(cache, f"v{i}", used=1_000_000 + i * 100)
    current = cache / "v0"  # the oldest
    _prune(cache, 2, current)
    assert _left(cache) == ["v0", "v4"], "CURRENT takes a slot and the newest other keeps the second"


def test_a_venv_in_use_is_kept_and_a_dead_runs_marker_is_not_use(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    _venv(cache, "busy", used=1_000_000, in_use=str(os.getpid()))  # this test's pid: alive
    _venv(cache, "stale", used=1_000_100, in_use=DEAD_PID)
    _venv(cache, "new", used=1_000_200)
    _prune(cache, 1, cache / "new")
    assert _left(cache) == ["busy", "new"], _left(cache)


def test_a_venv_a_live_process_runs_from_is_kept_without_a_marker(tmp_path: Path) -> None:
    # A run from before the markers: only its command line names the venv.
    cache = tmp_path / "cache"
    old = _venv(cache, "old", used=1_000_000)
    _venv(cache, "new", used=1_000_200)
    proc = subprocess.Popen(["bash", "-c", f'exec -a "{old}/bin/pytest" sleep 30'])
    try:
        _prune(cache, 1, cache / "new")
        assert _left(cache) == ["new", "old"], "a venv a live process runs from must be kept"
    finally:
        proc.kill()
        proc.wait()
    _prune(cache, 1, cache / "new")
    assert _left(cache) == ["new"], "once the process is gone it is pruned"


def test_nothing_but_venvs_is_touched_and_a_clean_cache_prints_nothing(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    other = cache / "not-a-venv"
    other.mkdir(parents=True)
    (other / "keep.txt").write_text("mine")
    _venv(cache, "a", used=1_000_000)
    _venv(cache, "b", used=1_000_100)
    assert _prune(cache, 6, cache / "b") == "", "within KEEP: no line"
    _prune(cache, 1, cache / "b")
    assert _left(cache) == ["b", "not-a-venv"] and (other / "keep.txt").exists()


def test_the_run_marks_its_venv_before_pruning_and_prunes_only_the_default_cache() -> None:
    text = LOCAL.read_text(encoding="utf-8")
    mark = text.index(': > "$venv/.in-use/$$"')
    used = text.index('touch "$venv/.last-used"')
    prune = text.index('"$root/scripts/test-core-venv-prune.sh"')
    assert mark < prune and used < prune, "the run's own venv must be marked in use and used BEFORE pruning"
    guard = text.rindex('if [ -z "${NOO_TEST_CORE_VENV:-}" ]; then', 0, prune)
    assert prune - guard < 200, "only the default cache is pruned, never a venv path the caller chose"
    assert '"${NOO_TEST_CORE_VENV_KEEP:-6}"' in text


def _floor_part() -> str:
    """The disk-floor lines of test-core-local.sh, run alone with a fake df."""
    text = LOCAL.read_text(encoding="utf-8")
    start = text.index('min_gb="${NOO_BATCH_MIN_DISK_GB:-15}"')
    end = text.index("# This run's venv is in use")
    return text[start:end]


def _run_floor(tmp_path: Path, avail_kb: int, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    df = bindir / "df"
    df.write_text(f"#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted'\necho '/dev/x 1000 1 {avail_kb} 1% /'\n")
    df.chmod(0o755)
    script = f'set -euo pipefail\nvenv="{tmp_path}/cache/not-yet/v"\n{_floor_part()}\necho STARTED\n'
    e = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    e.update(env or {})
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e)


def test_a_run_refuses_to_start_below_the_disk_floor_and_says_why(tmp_path: Path) -> None:
    gb = 1024 * 1024
    low = _run_floor(tmp_path, 4 * gb)
    assert low.returncode == 1 and "STARTED" not in low.stdout, low
    assert "only 4 GB free" in low.stderr and "at least 15 GB is needed (NOO_BATCH_MIN_DISK_GB)" in low.stderr, low.stderr
    assert "STARTED" in _run_floor(tmp_path, 16 * gb).stdout, "above the floor it starts"
    assert "STARTED" in _run_floor(tmp_path, 4 * gb, {"NOO_BATCH_MIN_DISK_GB": "2"}).stdout, "the knob is noo-batch's"
    bad = _run_floor(tmp_path, 16 * gb, {"NOO_BATCH_MIN_DISK_GB": "lots"})
    assert bad.returncode == 1 and "not a whole number" in bad.stderr
