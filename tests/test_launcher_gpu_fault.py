# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A GPU fault must not take the controller down (i277e; pop-os, 2026-10-28).

The GPU embed container failed at start with the CDI error
"error getting device handle for index '0': Unknown Error"; compose aborted
the whole `up` and the gateway, evolve, grafana and the embed doors stayed
Created until a reboot. A GPU service is optional to the core:

* the launcher (scripts/lib-stuck-container.sh) holds every service whose
  container recorded a GPU device error, by name, starts every OTHER service
  (the gateway included) and exits 75 with the hold in NOO_STUCK_REPORT;
* a second GPU service failing the retry is held the same way;
* the Created guard does not `docker start` a held service again;
* in the compose file no service that needs no GPU waits on one that does,
  so the CPU embedder (ollama-embed-cpu) comes up without the GPU embedder.

A fake `docker` on PATH stands in for the daemon; nothing real is touched.
"""

from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"

GPU_ERR = (
    "Error response from daemon: failed to create task for container: failed to create shim task: "
    "OCI runtime create failed: could not apply required modification to OCI specification: "
    "error modifying OCI spec: failed to inject CDI devices: failed to inject devices: "
    "error getting device handle for index '0': Unknown Error"
)

# Container ids are the service names prefixed with `cid-`; $STATE holds
# one "<service> <status>" line per container the fake daemon knows.
FAKE_DOCKER = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
svc_of() { echo "${1#cid-}"; }
status_of() { awk -v s="$1" '$1==s {print $2}' "$STATE"; }
case "$*" in
  *"config --services"*) printf '%s\n' postgres redis gateway grafana stunnel-ollama-embed ollama-embed ollama-embed-cpu nvidia-exporter ;;
  *" ps -aq"*) awk '{print "cid-" $1}' "$STATE" ;;
  "inspect -f {{.Name}} "*) echo "/noo-$(svc_of "$4")" ;;
  "inspect -f {{ index .Config.Labels"*|"inspect --format {{ index .Config.Labels"*) svc_of "${@: -1}" ;;
  "inspect -f {{.State.Status}} {{.State.Error}} "*)
    s="$(svc_of "$4")"; st="$(status_of "$s")"
    case " $FAKE_GPU_BAD " in *" $s "*) [ "$st" = created ] && { echo "created $GPU_ERR"; exit 0; } ;; esac
    echo "${st:-running} " ;;
  "inspect -f {{.State.Error}} "*) echo "$GPU_ERR" ;;
  "inspect --format {{.State.Status}} "*) status_of "$(svc_of "$4")" ;;
  "start "*) echo "STARTED $2" >> "$FAKE_LOG" ;;
  *" up "*)
    # Services named after the flags, or every service when none is.
    want="$(printf '%s\n' "$@" | awk 'f && !/^-/ && prev !~ /^--scale$/ {print} {prev=$0} $0=="up"{f=1}')"
    [ -n "$want" ] || want="$(awk '{print $1}' "$STATE")"
    rc=0
    for s in $want; do
      case " $FAKE_GPU_BAD " in *" $s "*)
        sed -i "s/^$s .*/$s created/" "$STATE"; rc=1; continue ;; esac
      sed -i "s/^$s .*/$s running/" "$STATE"
    done
    [ "$rc" = 0 ] || { echo "$GPU_ERR" >&2; exit 1; }
    exit 0 ;;
  *) exit 0 ;;
esac
"""

ALL = ["postgres", "redis", "gateway", "grafana", "stunnel-ollama-embed", "ollama-embed",
       "ollama-embed-cpu", "nvidia-exporter"]


def _run(tmp_path: Path, gpu_bad: str, guard: bool = False):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    d = bin_dir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(0o755)
    log = tmp_path / "docker.log"
    report = tmp_path / "report"
    state = tmp_path / "state"
    state.write_text("".join(f"{s} created\n" for s in ALL))
    guard_line = (
        'NOO_CREATED_GUARD_WAIT=0 NOO_CREATED_GUARD_SERVICES="' + " ".join(ALL) + '" '
        "noo_created_guard $(docker compose -f a.yml ps -aq)"
        if guard else ":"
    )
    script = textwrap.dedent(f"""
        . {SCRIPTS}/lib-ui.sh
        . {SCRIPTS}/lib-stuck-container.sh
        . {SCRIPTS}/lib-created-guard.sh
        noo_compose_up_isolating_stuck compose -f a.yml --profile controller up -d --force-recreate --scale node-agent=0
        rc=$?
        {guard_line}
        echo "RC=$rc HELD=[$NOO_ISOLATED_SERVICES]"
    """)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "STATE": str(state),
        "FAKE_GPU_BAD": gpu_bad,
        "GPU_ERR": GPU_ERR,
        "NOO_STUCK_REPORT": str(report),
        "NO_COLOR": "1",
        "LC_ALL": "C",
    }
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=60)
    m = re.search(r"RC=(\d+) HELD=\[([^\]]*)\]", p.stdout)
    assert m, p.stdout + p.stderr
    states = dict(line.split() for line in state.read_text().splitlines())
    calls = log.read_text().splitlines() if log.exists() else []
    return p, int(m.group(1)), m.group(2).split(), states, report, calls


def test_a_gpu_fault_holds_the_gpu_service_and_the_gateway_still_starts(tmp_path):
    p, rc, held, states, report, calls = _run(tmp_path, "ollama-embed")
    out = p.stdout + p.stderr
    assert rc == 75, out
    assert held == ["ollama-embed"], out
    assert states["ollama-embed"] == "created"
    for svc in ("gateway", "postgres", "redis", "grafana", "stunnel-ollama-embed", "ollama-embed-cpu",
                "nvidia-exporter"):
        assert states[svc] == "running", (svc, states, out)
    assert "noo-ollama-embed (ollama-embed) is held: the GPU did not answer when it started" in out, out
    assert "error getting device handle for index '0'" in out, out
    assert "the CPU embedder (ollama-embed-cpu) takes the embeddings" in out, out
    retry = [c for c in calls if " up " in f" {c} " and "--no-deps" in c]
    assert len(retry) == 1 and " ollama-embed " not in f" {retry[0]} " and "gateway" in retry[0], retry
    assert "--force-recreate" in retry[0] and "--scale node-agent=0" in retry[0], retry
    assert report.read_text().split("\n")[:2] == ["ollama-embed", "cid-ollama-embed gpu"]


def test_a_second_gpu_service_failing_the_retry_is_held_too(tmp_path):
    # The exporter reserves the GPU as well; it fails the first retry.
    p, rc, held, states, report, _ = _run(tmp_path, "ollama-embed nvidia-exporter")
    out = p.stdout + p.stderr
    assert rc == 75, out
    assert sorted(held) == ["nvidia-exporter", "ollama-embed"], out
    assert states["gateway"] == "running" and states["ollama-embed-cpu"] == "running", (states, out)
    assert states["nvidia-exporter"] == "created" and states["ollama-embed"] == "created"
    assert report.read_text().count(" gpu\n") == 2


def test_the_created_guard_leaves_a_held_service_alone(tmp_path):
    p, rc, held, states, _, calls = _run(tmp_path, "ollama-embed", guard=True)
    assert rc == 75 and held == ["ollama-embed"], p.stdout + p.stderr
    assert not any(c.startswith("STARTED") and "ollama-embed" in c and "cpu" not in c for c in calls), calls
    assert not any(c.startswith("start ") and c.endswith("cid-ollama-embed") for c in calls), calls


def test_a_clean_up_holds_nothing(tmp_path):
    p, rc, held, states, report, _ = _run(tmp_path, "")
    assert rc == 0 and held == [], p.stdout + p.stderr
    assert all(v == "running" for v in states.values()), states
    assert not report.exists()


# ── compose structure ──

def _services() -> dict:
    svcs: dict = {}
    for f in ("docker-compose.cluster.yml", "docker-compose.gpu-embed.yml"):
        doc = yaml.safe_load((REPO_ROOT / f).read_text())
        for name, body in (doc.get("services") or {}).items():
            merged = svcs.setdefault(name, {})
            for k, v in (body or {}).items():
                merged[k] = v if k not in merged or not isinstance(v, dict) else {**merged[k], **v}
    return svcs


def _needs_gpu(body: dict) -> bool:
    devs = (((body.get("deploy") or {}).get("resources") or {}).get("reservations") or {}).get("devices") or []
    return any(d.get("driver") == "nvidia" for d in devs)


def _hard_deps(body: dict) -> list[str]:
    deps = body.get("depends_on") or []
    if isinstance(deps, list):
        return list(deps)
    return [n for n, spec in deps.items() if (spec or {}).get("required", True) is not False]


def test_no_service_without_a_gpu_waits_on_one_with_a_gpu():
    svcs = _services()
    gpu = {n for n, b in svcs.items() if _needs_gpu(b)}
    assert {"ollama-embed", "vllm", "ollama", "nvidia-exporter"} <= gpu, gpu
    bad = []
    for name, body in svcs.items():
        if name in gpu:
            continue
        seen, todo = set(), _hard_deps(body)
        while todo:
            d = todo.pop()
            if d in seen:
                continue
            seen.add(d)
            if d in gpu:
                bad.append(f"{name} -> {d}")
            todo.extend(_hard_deps(svcs.get(d) or {}))
    assert not bad, f"a GPU fault would hold these with the GPU service: {bad}"


def test_the_cpu_embedder_does_not_wait_on_the_gpu_embedder():
    svcs = _services()
    assert "ollama-embed" not in _hard_deps(svcs["ollama-embed-cpu"])
    assert not _needs_gpu(svcs["ollama-embed-cpu"])


# ── the pre-check: the overlay is not requested of a GPU that cannot answer ──

def _probe(tmp_path, smi=None, lspci=None, fn="_compose_gpu_state"):
    """Run a lib-compose.sh function with fake nvidia-smi / lspci first on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in (("nvidia-smi", smi), ("lspci", lspci)):
        if body is not None:
            f = bindir / name
            f.write_text("#!/bin/bash\n" + body + "\n")
            f.chmod(0o755)
    # A PATH holding only the fakes and the basic tools, so the host's own
    # nvidia-smi can never answer for the test.
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    for t in ("grep", "cat", "dirname", "sed", "tr", "head", "printf", "echo"):
        src = subprocess.run(["bash", "-c", f"command -v {t}"], capture_output=True, text=True).stdout.strip()
        if src.startswith("/") and not (tools / t).is_symlink():
            (tools / t).symlink_to(src)
    env = {"PATH": f"{bindir}:{tools}", "HOME": str(tmp_path)}
    r = subprocess.run(
        ["/bin/bash", "-c", f". {SCRIPTS}/lib-compose.sh && {fn}"],
        capture_output=True, text=True, env=env, cwd=str(tmp_path),
    )
    return r


SMI_OK = 'case "$*" in -L) echo "GPU 0: RTX 3060";; *) echo 6144;; esac'
SMI_LOST = 'echo "Unable to determine the device handle for GPU0: Unknown Error" >&2; exit 255'
SMI_LISTS_BUT_NO_HANDLE = 'case "$*" in -L) echo "GPU 0: RTX 3060";; *) echo "Unknown Error" >&2; exit 255;; esac'
# A unified-memory GPU (GB10, Jetson): memory.total is "[N/A]", the index answers.
SMI_UNIFIED = 'case "$*" in -L) echo "GPU 0: NVIDIA GB10";; *query-gpu=index*) echo 0;; *) echo "[N/A]";; esac'
LSPCI_NVIDIA = 'echo "01:00.0 VGA compatible controller: NVIDIA Corporation GA106M [GeForce RTX 3060 Mobile]"'


def test_a_working_gpu_is_ok_and_prints_no_notice(tmp_path):
    for smi in (SMI_OK, SMI_UNIFIED):
        assert _probe(tmp_path, smi=smi).stdout.strip() == "ok", smi
        r = _probe(tmp_path, smi=smi, fn="compose_gpu_notice")
        assert r.stdout == "" and r.stderr == "", smi


def test_a_driver_that_lost_the_gpu_is_lost_and_the_notice_names_cause_and_choice(tmp_path):
    for smi in (SMI_LOST, SMI_LISTS_BUT_NO_HANDLE):
        assert _probe(tmp_path, smi=smi).stdout.strip() == "lost", smi
    r = _probe(tmp_path, smi=SMI_LOST, fn="compose_gpu_notice")
    assert "the NVIDIA driver lost the GPU (nvidia-smi cannot read it): the embedder starts on CPU; reboot to get the GPU back" in r.stderr, r.stderr
    assert len(r.stderr.strip().splitlines()) == 1


def test_no_nvidia_driver_is_none_with_or_without_a_card(tmp_path):
    # A card with no driver installed is a box set up without the NVIDIA
    # stack: no fault to name on every start.
    for lspci in (LSPCI_NVIDIA, "echo '00:02.0 VGA compatible controller: Intel'"):
        assert _probe(tmp_path, lspci=lspci).stdout.strip() == "none", lspci
        r = _probe(tmp_path, lspci=lspci, fn="compose_gpu_notice")
        assert r.stderr == "", "no driver is not a fault"


def test_the_overlay_is_requested_only_of_a_gpu_that_answers(tmp_path):
    for smi, want in ((SMI_OK, 0), (SMI_UNIFIED, 0), (SMI_LOST, 1), (SMI_LISTS_BUT_NO_HANDLE, 1)):
        assert _probe(tmp_path, smi=smi, fn="_compose_gpu_visible").returncode == want, smi


def test_both_launchers_print_the_notice_after_the_file_list():
    for name in ("noomesh-start.sh", "noomesh-restart.sh"):
        body = (SCRIPTS / name).read_text()
        i = body.index('COMPOSE_FILES="$(compose_file_args .)"')
        assert "compose_gpu_notice" in body[i : i + 120], name
