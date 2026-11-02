# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A stuck nvidia-smi must not stall the launchers (0.6.16; awolf, 2026-10-31).

On a WSL2 node whose GPU a Windows program is using, one `nvidia-smi` call
blocked 11 minutes, uninterruptibly, in the dxg driver. `timeout 5 nvidia-smi`
returned only after 665 s: GNU timeout waits for its child after signalling
it. So scripts/lib-compose.sh bounds the probe itself
(`_noo_nvidia_smi_bounded`): background child, output in a temp file, poll,
and on the deadline kill-and-abandon, status 124. A stuck GPU is "busy": the
driver is there, the GPU did not answer, and the GPU overlay is KEPT.

The fakes below ignore SIGTERM (`trap '' TERM`) and sleep 30 s, which is the
worst case short of D-state: the probe must return anyway.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"

SMI_SLEEPS = "trap '' TERM; sleep 30"
SMI_OK = 'case "$*" in -L) echo "GPU 0: RTX 3060";; *) echo 6144;; esac'
SMI_LOST = 'echo "Unable to determine the device handle for GPU0: Unknown Error" >&2; exit 255'
DEADLINE = 2  # NOO_GPU_PROBE_SECS in the tests: keeps the suite quick


def _env(tmp_path: Path, smi: str | None) -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    if smi is not None:
        f = bindir / "nvidia-smi"
        f.write_text("#!/bin/bash\n" + smi + "\n")
        f.chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir(parents=True, exist_ok=True)
    for t in ("grep", "cat", "dirname", "sed", "tr", "head", "printf", "echo",
              "mktemp", "sleep", "rm", "mv", "ls"):
        src = subprocess.run(["bash", "-c", f"command -v {t}"], capture_output=True, text=True).stdout.strip()
        if src.startswith("/") and not (tools / t).is_symlink():
            (tools / t).symlink_to(src)
    tmp = tmp_path / "tmp"
    tmp.mkdir(exist_ok=True)
    return {"PATH": f"{bindir}:{tools}", "HOME": str(tmp_path), "TMPDIR": str(tmp),
            "NOO_GPU_PROBE_SECS": str(DEADLINE)}


def _run(tmp_path: Path, smi: str | None, fn: str, shell: str = "/bin/bash"):
    t0 = time.monotonic()
    r = subprocess.run(
        [shell, "-c", f". {SCRIPTS}/lib-compose.sh && {fn}"],
        capture_output=True, text=True, env=_env(tmp_path, smi), cwd=str(tmp_path), timeout=60,
    )
    return r, time.monotonic() - t0


# ── the helper alone ──

def test_helper_a_fast_command_returns_its_output_and_status(tmp_path):
    r, took = _run(tmp_path, SMI_OK, '_noo_nvidia_smi_bounded 5 -L; echo "RC=$?"')
    assert r.stdout.splitlines() == ["GPU 0: RTX 3060", "RC=0"], r
    assert took < 3, took


def test_helper_passes_through_a_failing_status(tmp_path):
    r, _ = _run(tmp_path, SMI_LOST, '_noo_nvidia_smi_bounded 5 -L; echo "RC=$?"')
    assert "RC=255" in r.stdout and "Unknown Error" in r.stdout, r


def test_helper_a_sleeper_returns_124_within_the_deadline(tmp_path):
    r, took = _run(tmp_path, SMI_SLEEPS, f'_noo_nvidia_smi_bounded {DEADLINE} -L; echo "RC=$?"')
    assert r.stdout.strip() == "RC=124", r
    assert took < DEADLINE + 2, took


def test_helper_a_sleeper_does_not_hold_a_command_substitution_open(tmp_path):
    # The stuck child must not keep the caller's captured stdout open.
    r, took = _run(tmp_path, SMI_SLEEPS, f'out="$(_noo_nvidia_smi_bounded {DEADLINE} -L)"; echo "RC=$? [$out]"')
    assert r.stdout.strip() == "RC=124 []", r
    assert took < DEADLINE + 2, took


def test_helper_leaves_no_temp_dir_behind_even_when_abandoning(tmp_path):
    _run(tmp_path, SMI_SLEEPS, f"_noo_nvidia_smi_bounded {DEADLINE} -L")
    _run(tmp_path, SMI_OK, "_noo_nvidia_smi_bounded 5 -L")
    assert list((tmp_path / "tmp").iterdir()) == []


def test_helper_works_under_a_posix_sh_too(tmp_path):
    # lib-compose.sh as a whole wants bash to find its siblings; the helper
    # itself is POSIX, so lift it out and run it under dash.
    sh = "/bin/dash" if Path("/bin/dash").exists() else "/bin/sh"
    body = (SCRIPTS / "lib-compose.sh").read_text().split("_noo_nvidia_smi_bounded() {", 1)[1]
    func = "_noo_nvidia_smi_bounded() {" + body.split("\n}\n", 1)[0] + "\n}\n"
    r, took = _run(tmp_path, SMI_SLEEPS, "true", shell=sh)  # builds the env
    t0 = time.monotonic()
    r = subprocess.run([sh, "-c", f'{func}\n_noo_nvidia_smi_bounded {DEADLINE} -L; echo "RC=$?"'],
                       capture_output=True, text=True, env=_env(tmp_path, SMI_SLEEPS), timeout=60)
    assert r.stdout.strip() == "RC=124", r
    assert time.monotonic() - t0 < DEADLINE + 2


# ── the state ──

def test_a_stuck_gpu_is_busy_in_under_the_deadline(tmp_path):
    r, took = _run(tmp_path, SMI_SLEEPS, "_compose_gpu_state")
    assert r.stdout.strip() == "busy", r
    assert took < 2 * DEADLINE, took


def test_the_other_states_are_unchanged(tmp_path):
    assert _run(tmp_path, SMI_OK, "_compose_gpu_state")[0].stdout.strip() == "ok"
    assert _run(tmp_path, SMI_LOST, "_compose_gpu_state")[0].stdout.strip() == "lost"
    assert _run(tmp_path / "x", None, "_compose_gpu_state")[0].stdout.strip() == "none"


def test_busy_prints_one_line_and_does_not_claim_the_gpu_is_lost(tmp_path):
    r, _ = _run(tmp_path, SMI_SLEEPS, 'compose_gpu_notice; echo "LOST=${NOO_GPU_LOST:-}"')
    lines = r.stderr.rstrip("\n").splitlines()
    assert lines == [f"  the GPU did not answer nvidia-smi within {DEADLINE} s (busy: on WSL2 a Windows "
                     "program is likely using it); the GPU overlay is kept"], r
    assert r.stdout.strip() == "LOST=", "busy is not lost: lib-stuck-container must not say 'lost, above'"


def test_busy_keeps_the_gpu_overlay_in_the_file_list(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for f in ("docker-compose.cluster.yml", "docker-compose.gpu-embed.yml"):
        (root / f).write_text("services: {}\n")
    r, _ = _run(tmp_path, SMI_SLEEPS, f"compose_file_list {root}")
    assert str(root / "docker-compose.gpu-embed.yml") in r.stdout.splitlines(), r
    r, _ = _run(tmp_path, SMI_LOST, f"compose_file_list {root}")
    assert str(root / "docker-compose.gpu-embed.yml") not in r.stdout.splitlines(), "lost still drops it"


def test_the_override_still_wins_over_a_stuck_probe(tmp_path):
    t0 = time.monotonic()
    r = subprocess.run(
        ["/bin/bash", "-c", f". {SCRIPTS}/lib-compose.sh && NOO_COMPOSE_GPU=0 _compose_gpu_state"],
        capture_output=True, text=True, env=_env(tmp_path, SMI_SLEEPS), cwd=str(tmp_path), timeout=60,
    )
    assert r.stdout.strip() == "none" and time.monotonic() - t0 < 2


# ── noomesh-restart.sh's VRAM check ──

def _detect_gpu_tier(tmp_path: Path, smi: str):
    """Run restart.sh's own detect_gpu_tier, lifted out of the script."""
    body = (SCRIPTS / "noomesh-restart.sh").read_text().split("detect_gpu_tier() {", 1)[1]
    func = "detect_gpu_tier() {" + body.split("\n}\n", 1)[0] + "\n}\n"
    return _run(tmp_path, smi, f'{func}\nprintf "[%s]" "$(detect_gpu_tier)"', shell="/bin/bash")


def test_restart_vram_check_treats_a_stuck_gpu_as_unknown(tmp_path):
    r, took = _detect_gpu_tier(tmp_path, SMI_SLEEPS)
    assert r.stdout == "[]", r
    assert took < DEADLINE + 2, took


def test_restart_vram_check_still_reads_a_working_gpu(tmp_path):
    r, _ = _detect_gpu_tier(tmp_path, 'echo 12288')
    assert r.stdout != "[]" and r.stdout.startswith("[") , r


def test_no_launcher_calls_nvidia_smi_unbounded():
    for name in ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh", "noomesh-stop.sh"):
        for n, line in enumerate((SCRIPTS / name).read_text().splitlines(), 1):
            s = line.strip()
            if s.startswith("#") or "nvidia-smi" not in s or "command -v nvidia-smi" in s:
                continue
            assert "_noo_nvidia_smi_bounded" in s, f"{name}:{n}: {s}"
