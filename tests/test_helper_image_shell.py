# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher scripts' throwaway helper container is the stack's own nginx.

scripts/lib-helper-image.sh is the shell twin of noo-cli/src/helper_image.rs:
the same reference (compose `model-cache` repo:tag, digest from the host's
stack.lock nginx row, else the compose default), the same job -> capability
table, the same flags. These tests prove the twins agree, that each shell job
runs the exact argv with only its one mount, and that no runtime script names
Docker Hub's alpine/busybox/hello-world."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-helper-image.sh"
RS = (ROOT / "noo-cli/src/helper_image.rs").read_text()
COMPOSE = (ROOT / "docker-compose.cluster.yml").read_text()
LINE = re.search(r"^\s*image: (ghcr\.io/noomesh/nginx:[\w.-]+)\$\{NOO_IMAGE_DIGEST_NGINX:-(@sha256:[0-9a-f]{64})\}\s*$", COMPOSE, re.M)
REPO_TAG, DEFAULT_DIGEST = LINE.group(1), LINE.group(2)
FLAGS = ["run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL"]


def _sh(code: str, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", f'. "{LIB}"; {code}'], capture_output=True, text=True,
                          env={**os.environ, **(env or {})}, cwd=cwd)


# ── parity with helper_image.rs ──────────────────────────────────────────────

def test_the_reference_is_the_compose_line_without_a_lock(tmp_path):
    r = _sh("helper_image_ref", {"NOO_STACK_LOCK": str(tmp_path / "none.lock")})
    assert r.stdout.strip() == REPO_TAG + DEFAULT_DIGEST, r.stderr


def test_the_lock_nginx_row_wins_and_other_rows_do_not(tmp_path):
    lock = tmp_path / "stack.lock"
    lock.write_text("# stack v0.6.29\ngateway@sha256:" + "a" * 64 + "\nnginx@sha256:" + "b" * 64 + "\n")
    assert _sh("helper_image_ref", {"NOO_STACK_LOCK": str(lock)}).stdout.strip() == f"{REPO_TAG}@sha256:{'b' * 64}"
    lock.write_text("# stack v0.6.1\ngateway@sha256:" + "a" * 64 + "\n")   # a lock with no nginx row
    assert _sh("helper_image_ref", {"NOO_STACK_LOCK": str(lock)}).stdout.strip() == REPO_TAG + DEFAULT_DIGEST


def test_the_rust_twin_pins_the_same_compose_line():
    # helper_image.rs includes this very compose file and parses this very line.
    assert 'include_str!("../../docker-compose.cluster.yml")' in RS
    assert "ghcr.io/noomesh/nginx:" in RS and "NOO_IMAGE_DIGEST_NGINX" in RS


def _rust_table() -> dict[str, list[str]]:
    body = RS[RS.index("pub(crate) const JOB_CAPS"):]
    body = body[: body.index("];")]
    return {m.group(1): re.findall(r'"([A-Z_]+)"', m.group(2))
            for m in re.finditer(r'\("([a-z-]+)", &\[([^\]]*)\]', body)}


def test_the_shell_cap_table_equals_the_rust_table():
    rust = _rust_table()
    assert len(rust) >= 8 and {"touch", "chown", "du", "wipe", "reown", "data-dirs", "chgrp-file", "secrets-chown"} <= set(rust)
    for job, caps in rust.items():
        assert _sh(f"helper_job_caps {job}").stdout.split() == caps, job
    r = _sh("helper_job_caps not-a-job")
    assert r.returncode != 0 and "no capability row" in r.stderr
    # and the shell knows no job the Rust table lacks
    shell_jobs = set(re.findall(r"^\s+([a-z-]+)\)\s+printf", LIB.read_text(), re.M))
    assert shell_jobs == set(rust)


# ── argv per job, with a fake docker ─────────────────────────────────────────

REF = REPO_TAG + DEFAULT_DIGEST


def _run_job(tmp_path, snippet: str, env: dict | None = None) -> list[list[str]]:
    """Run `snippet` with a fake docker that logs each call's argv (one call per
    line, args joined by \\x1f). `image inspect` succeeds, so nothing pulls."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    log.write_text("")
    d = bindir / "docker"
    d.write_text('#!/bin/bash\nprintf "%s" "$1" >> "$LOG"; shift; for a in "$@"; do printf "\\x1f%s" "$a" >> "$LOG"; done; echo >> "$LOG"\n')
    d.chmod(0o755)
    e = {"PATH": f"{bindir}:{os.environ['PATH']}", "LOG": str(log), "NOO_STACK_LOCK": str(tmp_path / "none.lock"), **(env or {})}
    r = _sh(snippet, e, cwd=tmp_path)
    assert r.returncode == 0, (r.stdout, r.stderr)
    return [l.split("\x1f") for l in log.read_text().splitlines()]


def _only_run(calls):
    runs = [c for c in calls if c[0] == "run"]
    assert len(runs) == 1, calls
    return runs[0]


def test_the_helper_never_pulls_when_the_image_is_present(tmp_path):
    calls = _run_job(tmp_path, "helper_ensure_present")
    assert calls == [["image", "inspect", REF]], calls


def test_the_helper_pulls_by_digest_only_when_inspect_fails(tmp_path):
    bindir = tmp_path / "bin"; bindir.mkdir()
    log = tmp_path / "l"
    (bindir / "docker").write_text('#!/bin/bash\necho "$*" >> "$LOG"\n[ "$1 $2" = "image inspect" ] && exit 1\nexit 0\n')
    (bindir / "docker").chmod(0o755)
    r = _sh("helper_ensure_present", {"PATH": f"{bindir}:{os.environ['PATH']}", "LOG": str(log), "NOO_STACK_LOCK": str(tmp_path / "x")})
    assert r.returncode == 0, r.stderr
    assert log.read_text().splitlines() == [f"image inspect {REF}", f"pull -q {REF}"]


def _expect(caps, mount, ep="sh", image=REF):
    v = FLAGS[:]
    for c in caps:
        v += ["--cap-add", c]
    return v + ["--security-opt", "no-new-privileges", "--entrypoint", ep, "-v", mount, image]


@pytest.mark.parametrize("job,caps,mount,ep", [
    ("data-dirs", ["CHOWN", "DAC_OVERRIDE"], "proj_noo-data:/d", "sh"),
    ("reown", ["CHOWN", "DAC_OVERRIDE"], "/srv/redis:/d", "sh"),
    ("wipe", ["CHOWN", "DAC_OVERRIDE"], "/srv/pg:/wipe", "sh"),
    ("secrets-chown", ["CHOWN", "DAC_READ_SEARCH"], "/run/noo/secrets:/d", "sh"),
    ("chgrp-file", ["CHOWN", "FOWNER"], "/w/noomesh.yaml:/f", "sh"),
])
def test_exact_argv_for_each_shell_job(tmp_path, job, caps, mount, ep):
    run = _only_run(_run_job(tmp_path, f"helper_run {job} {ep} {mount} -c true"))
    assert run[1:] == _expect(caps, mount, ep)[1:] + ["-c", "true"]
    assert "--privileged" not in run and run.count("-v") == 1


def test_an_operator_image_replaces_only_the_image(tmp_path):
    run = _only_run(_run_job(tmp_path, "helper_run secrets-chown sh /s:/d -c true", {"HELPER_IMAGE_OVERRIDE": "registry.example/chown:1@sha256:" + "c" * 64}))
    assert run[1:] == _expect(["CHOWN", "DAC_READ_SEARCH"], "/s:/d", image="registry.example/chown:1@sha256:" + "c" * 64)[1:] + ["-c", "true"]


# ── the real launcher paths use the helper ───────────────────────────────────

def test_the_launcher_paths_call_the_helper_with_their_job():
    want = {
        "noomesh-start.sh": "helper_run chgrp-file sh",
        "lib-instance.sh": "helper_run data-dirs sh",
        "lib-reown.sh": "helper_run reown sh",
        "lib-secrets.sh": "helper_argv secrets-chown sh",
        "noomesh-clean.sh": "helper_run wipe sh",
    }
    for f, call in want.items():
        text = (ROOT / "scripts" / f).read_text()
        assert call in text, f
        assert "helper_ensure_present" in text, f"{f} pulls the helper before its first run"


# ── no runtime script names a Docker Hub helper image ────────────────────────

# DEV/TEST/CI-only scripts, each carrying a comment that says so.
DEV_ONLY = {"sqlx-prepare.sh", "build-hardened-llamacpp.sh", "test-rotation-rehearsal.sh"}


def test_no_runtime_script_runs_alpine_busybox_or_hello_world():
    bad = re.compile(r"\b(alpine|busybox|hello-world)\b")
    hits = []
    for f in sorted((ROOT / "scripts").rglob("*.sh")):
        if f.name in DEV_ONLY:
            assert "-ONLY" in f.read_text(), f"{f.name} must say it is dev/test-only"
            continue
        for n, line in enumerate(f.read_text().splitlines(), 1):
            code = re.sub(r"(^|\s)#.*", "", line)
            if bad.search(code):
                hits.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not hits, "a Docker Hub image on a runtime path (use scripts/lib-helper-image.sh):\n" + "\n".join(hits)
