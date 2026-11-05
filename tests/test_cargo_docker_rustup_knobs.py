# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""cargo-docker.sh's batch-only knobs: a persistent RUSTUP_HOME and a bounded
toolchain step.

The build batch (noomesh-internal ops/batch/noo-batch.sh) re-synced the pinned
toolchain on every run, and on 2026-11-05 one download stalled ~30 min while
holding the batch lock. `CARGO_DOCKER_RUSTUP_VOLUME` keeps the toolchain in a
named volume; `CARGO_DOCKER_TOOLCHAIN_TIMEOUT` bounds the install step, which
runs under `flock` because two batch builds may share the volume.

These are dev-harness knobs for ops tooling. Unset, the script must build
exactly as before, and nothing that ships, and no workflow, may set them.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/cargo-docker.sh"
KNOBS = ("CARGO_DOCKER_RUSTUP_VOLUME", "CARGO_DOCKER_TOOLCHAIN_TIMEOUT")


def _fake_docker(tmp: Path, *, volume_exists: bool = True) -> Path:
    """A `docker` that records `run` argv (NUL-separated) and answers the
    volume calls cargo-docker.sh makes."""
    bin_ = tmp / "bin"
    bin_.mkdir()
    (bin_ / "docker").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        case "$1 $2" in
          "volume inspect") exit {0 if volume_exists else 1} ;;
          "volume ls"|"volume create"|"volume rm") exit 0 ;;
        esac
        [ "$1" = run ] && printf '%s\\0' "$@" > "{tmp}/argv"
        exit 0
        """))
    (bin_ / "docker").chmod(0o755)
    return bin_


def _run_script(tmp: Path, env_extra: dict[str, str], *, volume_exists: bool = True) -> tuple[int, list[str], str]:
    bin_ = _fake_docker(tmp, volume_exists=volume_exists)
    env = {k: v for k, v in os.environ.items() if k not in KNOBS and not k.startswith("CARGO_DOCKER_")}
    env.update({"PATH": f"{bin_}:{env['PATH']}", "NOO_BUILD_SLOTS": "0", "CARGO_DOCKER_COMPONENTS": "clippy",
                "CARGO_DOCKER_CRATE": str(REPO / "noo-cli")}, **env_extra)
    p = subprocess.run(["bash", str(SCRIPT), "clippy", "--", "-D", "warnings"], cwd=REPO, env=env,
                       capture_output=True, text=True, timeout=60)
    argv = (tmp / "argv").read_text().split("\0")[:-1] if (tmp / "argv").exists() else []
    return p.returncode, argv, p.stderr


def test_unset_the_run_carries_no_rustup_volume_and_no_toolchain_step(tmp_path: Path) -> None:
    rc, argv, err = _run_script(tmp_path, {})
    assert rc == 0, err
    assert argv[:2] == ["run", "--rm"], argv
    assert not any("/usr/local/rustup" in a for a in argv), argv
    assert not any(a.startswith("NOO_TC_") for a in argv), argv
    assert "rustup component add clippy" in argv[-1] and "cargo  'clippy' '--' '-D' 'warnings'" in argv[-1]


def test_set_the_run_mounts_the_volume_once_and_passes_cargo_args_through(tmp_path: Path) -> None:
    rc, argv, err = _run_script(tmp_path, {"CARGO_DOCKER_RUSTUP_VOLUME": "noo-batch-rustup",
                                           "CARGO_DOCKER_TOOLCHAIN_TIMEOUT": "600"})
    assert rc == 0, err
    assert argv.count("noo-batch-rustup:/usr/local/rustup") == 1, argv
    assert "NOO_TC_TIMEOUT=600" in argv and "NOO_TC_COMPONENTS=clippy" in argv and "NOO_TC_REPO=/repo" in argv
    # cargo's args arrive as positional parameters, unquoted and unchanged.
    assert argv[-4:] == ["clippy", "--", "-D", "warnings"], argv
    assert argv[-5] == "sh", argv


@pytest.mark.parametrize("bad", ["", "10m", "-1", "1.5"])
def test_a_timeout_that_is_not_whole_seconds_is_refused(tmp_path: Path, bad: str) -> None:
    rc, argv, err = _run_script(tmp_path, {"CARGO_DOCKER_RUSTUP_VOLUME": "v", "CARGO_DOCKER_TOOLCHAIN_TIMEOUT": bad})
    if bad == "":
        assert rc == 0  # empty means the default
        assert "NOO_TC_TIMEOUT=900" in argv
    else:
        assert rc == 2 and not argv and "whole seconds" in err


def test_a_missing_volume_is_refused_not_minted_unlabelled(tmp_path: Path) -> None:
    rc, argv, err = _run_script(tmp_path, {"CARGO_DOCKER_RUSTUP_VOLUME": "v"}, volume_exists=False)
    assert rc == 2 and not argv and "does not exist" in err


# ── the in-container step, run on the host with a fake rustup and cargo ──


def _host_env(tmp: Path, *, rustup_body: str, timeout: str = "30", repo: Path | None = None) -> dict[str, str]:
    bin_ = tmp / "hbin"
    bin_.mkdir(exist_ok=True)
    (bin_ / "rustup").write_text("#!/bin/sh\n" + rustup_body)
    (bin_ / "cargo").write_text(f"#!/bin/sh\necho \"cargo $*\" >> {tmp}/events\n")
    for f in ("rustup", "cargo"):
        (bin_ / f).chmod(0o755)
    home = tmp / "rustup_home"
    home.mkdir(exist_ok=True)
    return {"PATH": f"{bin_}:{os.environ['PATH']}", "RUSTUP_HOME": str(home), "NOO_TC_TIMEOUT": timeout,
            "NOO_TC_COMPONENTS": "clippy", "NOO_TC_REPO": str(repo or tmp / "norepo")}


def _scripts() -> tuple[str, str]:
    sh = SCRIPT.read_text()
    tc_locked = sh.split("TC_LOCKED_SH='", 1)[1].split("\n'\n", 1)[0]
    tc_sh = sh.split("    TC_SH='", 1)[1].split("\n'\n", 1)[0]
    return tc_locked, tc_sh


def _run_step(tmp: Path, env: dict[str, str], tag: str = "") -> subprocess.CompletedProcess:
    tc_locked, tc_sh = _scripts()
    # Each build is its own container, so each has its own /tmp: give the
    # step-name file a per-run home by running in a private TMP dir.
    run_tmp = tmp / f"tmp{tag}"
    run_tmp.mkdir(exist_ok=True)
    body = tc_sh.replace("/tmp/noo-toolchain-step", f"{run_tmp}/noo-toolchain-step")
    locked = tc_locked.replace("/tmp/noo-toolchain-step", f"{run_tmp}/noo-toolchain-step")
    return subprocess.run(["sh", "-euc", body, "sh", "clippy", "-D", "warnings"],
                          env={**env, "NOO_TC_LOCKED_SH": locked}, capture_output=True, text=True, timeout=60)


RUSTUP_OK = """\
case "$1 $2" in
  "show active-toolchain") echo "1.99.0-x86_64-unknown-linux-gnu (overridden)" ;;
  "toolchain list") echo "1.99.0-x86_64-unknown-linux-gnu (active)" ;;
  "default ") echo "1.91.0-x86_64-unknown-linux-gnu (default)" ;;
esac
exit 0
"""


def test_the_step_installs_then_runs_cargo_with_its_args(tmp_path: Path) -> None:
    p = _run_step(tmp_path, _host_env(tmp_path, rustup_body=RUSTUP_OK))
    assert p.returncode == 0, p.stderr
    assert "toolchain step: rustup toolchain install --no-self-update" in p.stderr
    assert "toolchain step: rustup component add clippy" in p.stderr
    assert (tmp_path / "events").read_text().strip() == "cargo clippy -D warnings"


def test_cargo_s_exit_status_is_the_step_s_exit_status(tmp_path: Path) -> None:
    """The step `exec`s cargo, so nothing after it can mask a failing build."""
    env = _host_env(tmp_path, rustup_body=RUSTUP_OK)
    (Path(env["PATH"].split(":")[0]) / "cargo").write_text("#!/bin/sh\nexit 3\n")
    p = _run_step(tmp_path, env)
    assert p.returncode == 3, (p.returncode, p.stderr)


def test_a_stalled_install_times_out_naming_the_step_and_cargo_never_runs(tmp_path: Path) -> None:
    stall = 'case "$1 $2" in "toolchain install") sleep 30 ;; esac\nexit 0\n'
    p = _run_step(tmp_path, _host_env(tmp_path, rustup_body=stall, timeout="1"))
    assert p.returncode in (124, 137), (p.returncode, p.stderr)
    assert "TOOLCHAIN STEP TIMED OUT after 1s (rustup toolchain install --no-self-update)" in p.stderr, p.stderr
    assert not (tmp_path / "events").exists(), "cargo ran after a failed toolchain step"


def test_a_failed_install_fails_loud_naming_the_step(tmp_path: Path) -> None:
    fail = 'case "$1 $2" in "component add") exit 7 ;; esac\nexit 0\n'
    p = _run_step(tmp_path, _host_env(tmp_path, rustup_body=fail))
    assert p.returncode == 7
    assert "TOOLCHAIN STEP FAILED (exit 7, rustup component add clippy)" in p.stderr, p.stderr
    assert not (tmp_path / "events").exists()


def test_two_concurrent_builds_take_the_toolchain_step_one_at_a_time(tmp_path: Path) -> None:
    """Two installs into one RUSTUP_HOME at once is a race: the lock makes the
    steps strictly alternate, and the cargo step stays outside it."""
    log = tmp_path / "steps"
    body = f"""\
case "$1 $2" in
  "toolchain install") echo "enter $$" >> {log}; sleep 1; echo "leave $$" >> {log} ;;
  "show active-toolchain") echo "1.99.0-x86_64-unknown-linux-gnu" ;;
esac
exit 0
"""
    env = _host_env(tmp_path, rustup_body=body)
    results: list[subprocess.CompletedProcess] = []
    threads = [threading.Thread(target=lambda t=t: results.append(_run_step(tmp_path, env, t))) for t in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [r.returncode for r in results] == [0, 0], [r.stderr for r in results]
    lines = [ln.split()[0] for ln in log.read_text().splitlines()]
    assert lines == ["enter", "leave", "enter", "leave"], log.read_text()
    assert (tmp_path / "events").read_text().count("cargo clippy") == 2


def test_a_stuck_lock_holder_times_the_waiter_out_naming_the_wait(tmp_path: Path) -> None:
    env = _host_env(tmp_path, rustup_body=RUSTUP_OK, timeout="1")
    lock = Path(env["RUSTUP_HOME"]) / ".noo-batch.lock"
    holder = subprocess.Popen(["flock", str(lock), "sleep", "20"])
    try:
        import time
        time.sleep(0.3)
        p = _run_step(tmp_path, env)
    finally:
        holder.kill()
        holder.wait()
    assert p.returncode in (124, 137)
    assert "TOOLCHAIN STEP TIMED OUT after 1s (waiting for the toolchain lock)" in p.stderr, p.stderr


def test_the_sweep_removes_only_what_nothing_pins_uses_or_defaults_to(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    for crate, pin in (("gateway-rust", "1.99.0"), ("noo-cli", "1.99.0")):
        (repo / crate).mkdir(parents=True)
        (repo / crate / "rust-toolchain.toml").write_text(f'[toolchain]\nchannel = "{pin}"\n')
    removed = tmp_path / "removed"
    body = f"""\
case "$1 $2" in
  "show active-toolchain") echo "1.99.0-x86_64-unknown-linux-gnu (overridden)" ;;
  "default ") echo "1.91.0-x86_64-unknown-linux-gnu (default)" ;;
  "toolchain list") printf '%s\\n' 1.91.0-x86_64-unknown-linux-gnu "1.99.0-x86_64-unknown-linux-gnu (active)" \\
      1.98.0-x86_64-unknown-linux-gnu 1.100.0-x86_64-unknown-linux-gnu 1.97.0-x86_64-unknown-linux-gnu ;;
  "toolchain uninstall") echo "$3" >> {removed} ;;
esac
exit 0
"""
    env = _host_env(tmp_path, rustup_body=body, repo=repo)
    used = Path(env["RUSTUP_HOME"]) / ".noo-used"
    used.mkdir()
    # Another tree's build used 1.100.0 a minute ago; 1.97.0 was last used long ago.
    (used / "1.100.0-x86_64-unknown-linux-gnu").touch()
    old = used / "1.97.0-x86_64-unknown-linux-gnu"
    old.touch()
    os.utime(old, (0, 0))
    p = _run_step(tmp_path, env)
    assert p.returncode == 0, p.stderr
    assert sorted(removed.read_text().split()) == ["1.97.0-x86_64-unknown-linux-gnu", "1.98.0-x86_64-unknown-linux-gnu"]


def test_with_no_pin_found_the_sweep_removes_nothing(tmp_path: Path) -> None:
    removed = tmp_path / "removed"
    body = f"""\
case "$1 $2" in
  "toolchain list") echo 1.50.0-x86_64-unknown-linux-gnu ;;
  "toolchain uninstall") echo "$3" >> {removed} ;;
esac
exit 0
"""
    p = _run_step(tmp_path, _host_env(tmp_path, rustup_body=body))
    assert p.returncode == 0, p.stderr
    assert not removed.exists()


# ── P4: dev-harness knobs never set by anything that ships ──

SETS = re.compile(r"(?<![{\w])(" + "|".join(KNOBS) + r")\s*[=:]")


def _shipped_files() -> list[Path]:
    import json
    inputs = json.loads((REPO / "scripts/release-image-inputs.json").read_text())
    globs = {i for v in inputs["images"].values() for i in v.get("inputs", [])}
    globs |= {"noo-cli/**", ".github/workflows/**", "docker-compose*.yml", "deploy/**"}
    out: set[Path] = set()
    for g in globs:
        # `dir/**` yields only directories before Python 3.13: walk them.
        found = REPO.joinpath(g[:-3]).rglob("*") if g.endswith("/**") else REPO.glob(g)
        out.update(p for p in found if p.is_file() and not {".worktrees", "target", "node_modules"} & set(p.relative_to(REPO).parts))
    return sorted(out)


def test_nothing_that_ships_or_any_workflow_sets_the_knobs() -> None:
    files = _shipped_files()
    assert len(files) > 1000, f"scanned only {len(files)} files: this guard is looking in the wrong place"
    assert SCRIPT in files, "scripts/** is a shipped input; the scan must include cargo-docker.sh itself"
    hits = []
    for p in files:
        try:
            text = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if SETS.search(line):
                hits.append(f"{p.relative_to(REPO)}:{n}: {line.strip()}")
    assert not hits, "a dev-harness knob is set by a shipped path or a workflow (P4):\n" + "\n".join(hits)


def test_the_set_matcher_sees_an_assignment_and_not_a_read() -> None:
    assert SETS.search("CARGO_DOCKER_RUSTUP_VOLUME=noo-batch-rustup cargo-docker.sh")
    assert SETS.search("  CARGO_DOCKER_TOOLCHAIN_TIMEOUT: 600")
    assert SETS.search("export CARGO_DOCKER_RUSTUP_VOLUME=v")
    assert not SETS.search('RUSTUP_VOLUME="${CARGO_DOCKER_RUSTUP_VOLUME:-}"')
