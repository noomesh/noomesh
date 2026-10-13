# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""cargo-docker.sh bounds builds across EVERY session on the box.

host3 serves the fleet's vLLM on 19 GB; parallel builds from several sessions
starved it on 2026-10-02 and 2026-10-03. The bound must hold whoever starts
the build, so it is enforced in the shared script with flock slots and a free
memory floor. These tests run the script's own function, not a copy.
"""
import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SH = (REPO / "scripts/cargo-docker.sh").read_text()
FUNC = re.search(r"^acquire_build_slot\(\) \{.*?^\}", SH, re.S | re.M).group(0)


def run(script, env, timeout=8):
    full = {k: v for k, v in os.environ.items() if k != "CI"}
    full.update(env)
    return subprocess.run(["bash", "-c", FUNC + "\n" + script], env=full,
                          capture_output=True, text=True, timeout=timeout)


def test_every_docker_run_takes_a_slot_first():
    runs = [m.start() for m in re.finditer(r"exec docker run", SH)]
    assert runs, "no docker run found"
    for pos in runs:
        before = SH[:pos].rstrip().splitlines()[-1].strip()
        assert before == "acquire_build_slot", f"a docker run without a slot: {before!r}"


def test_a_held_slot_makes_the_next_build_wait(tmp_path):
    env = {"NOO_BUILD_SLOTS": "1", "NOO_BUILD_MIN_FREE_GB": "0",
           "NOO_BUILD_SLOT_DIR": str(tmp_path), "NOO_BUILD_SLOT_POLL": "1"}
    holder = subprocess.Popen(["bash", "-c", f"exec 9>>{tmp_path}/slot.1; flock 9; sleep 6"])
    try:
        import time; time.sleep(0.5)
        r = run("timeout 2 bash -c \"$(declare -f acquire_build_slot); acquire_build_slot\"; echo rc=$?", env)
        assert "rc=124" in r.stdout, r.stdout + r.stderr  # still waiting when timed out
        assert "waiting for a build slot" in r.stderr
    finally:
        holder.kill()


def test_a_free_slot_is_taken_at_once(tmp_path):
    env = {"NOO_BUILD_SLOTS": "2", "NOO_BUILD_MIN_FREE_GB": "0", "NOO_BUILD_SLOT_DIR": str(tmp_path)}
    r = run("acquire_build_slot && echo got", env)
    assert r.stdout.strip() == "got", r.stdout + r.stderr


def test_low_memory_waits_even_with_free_slots(tmp_path):
    env = {"NOO_BUILD_SLOTS": "2", "NOO_BUILD_MIN_FREE_GB": "100000",
           "NOO_BUILD_SLOT_DIR": str(tmp_path), "NOO_BUILD_SLOT_POLL": "1"}
    r = run("timeout 2 bash -c \"$(declare -f acquire_build_slot); acquire_build_slot\"; echo rc=$?", env)
    assert "rc=124" in r.stdout, r.stdout + r.stderr


def test_ci_and_the_escape_hatch_skip_the_bound(tmp_path):
    for extra in ({"CI": "true"}, {"NOO_BUILD_SLOTS": "0"}):
        env = {"NOO_BUILD_MIN_FREE_GB": "100000", "NOO_BUILD_SLOT_DIR": str(tmp_path), **extra}
        r = run("acquire_build_slot && echo got", env, timeout=5)
        assert r.stdout.strip() == "got", (extra, r.stdout + r.stderr)


def test_a_symlinked_crate_path_resolves_to_the_physical_tree(tmp_path):
    # $PWD keeps a symlink; git does not. A crate spelled through a symlink must
    # resolve to the same physical directory, or build.rs reads nothing and the
    # shared target volume caches an empty generated file.
    real = tmp_path / "real" / "repo" / "noo-cli"
    real.mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "real")
    block = SH[SH.index('CRATE_DIR="${CARGO_DOCKER_CRATE'):SH.index('IMAGE="${CARGO_DOCKER_IMAGE')]
    script = f'REPO_ROOT="{tmp_path}/real/repo"\n' + block + '\necho "$CRATE_DIR"'
    out = subprocess.run(["bash", "-c", script],
                         env={**os.environ, "CARGO_DOCKER_CRATE": str(link / "repo" / "noo-cli")},
                         capture_output=True, text=True).stdout.strip()
    assert out == str(real), out
