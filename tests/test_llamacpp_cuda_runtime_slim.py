# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CUDA llama-server image's runtime stage: security fixes and no dead weight.

On 2026-11-18 Trivy found 16 fixable HIGH in the published CUDA image, every
one in a package NVIDIA's runtime base ships at a stale version (gnupg x10,
apt x2, openssl x4). docker/Dockerfile.llamacpp-cuda's runtime stage now:

- upgrades from the Ubuntu SECURITY archive only (never NVIDIA's CUDA
  repository, which would move cuda-compat off the digest pin), and says that
  this makes the stage deliberately not byte-reproducible;
- purges gnupg and its tools, then apt, which nothing runs after the build;

and ci.yml's llamacpp-cuda-image job reports packages, size and the Trivy
findings of the image against its base, without failing on them.

The image itself is built only by hosted CI; these hold the form.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile.llamacpp-cuda"
CI = ROOT / ".github/workflows/ci.yml"

GNUPG = ("gnupg2", "gnupg", "gnupg-utils", "gpg", "gpg-agent", "gpgsm", "gpgconf", "dirmngr", "keyboxd")
APT = ("apt", "libapt-pkg6.0t64", "gpgv", "ubuntu-keyring")


def _runtime_stage() -> str:
    """The last stage, from its FROM line: the image that ships."""
    text = DOCKERFILE.read_text()
    starts = [m.start() for m in re.finditer(r"^FROM\s", text, re.M)]
    assert len(starts) == 2, f"expected builder + runtime stages, found {len(starts)}"
    stage = text[starts[-1]:]
    assert "nvidia/cuda:12.9.1-runtime-ubuntu24.04@sha256:" in stage.splitlines()[0], stage.splitlines()[0]
    return stage


def _commands(stage: str) -> str:
    """The stage without its comment lines (a comment must not satisfy a check)."""
    return "\n".join(line for line in stage.splitlines() if not line.lstrip().startswith("#"))


def _words(cmd: str) -> list[str]:
    return cmd.replace("\\\n", " ").replace(";", " ").split()


def test_runtime_stage_upgrades_from_the_security_archive_and_says_it_is_not_reproducible():
    stage = _runtime_stage()
    cmds = _commands(stage)
    assert "NOT BYTE-REPRODUCIBLE" in stage, "the runtime stage must say it is deliberately not byte-reproducible"
    # The upgrade source is the base's own noble-security stanza, and apt sees
    # nothing else while it upgrades.
    stanza = re.search(r"awk [^\n]*noble-security[^\n]*\\\n\s*/etc/apt/sources\.list\.d/ubuntu\.sources "
                       r"> /tmp/apt-security/security\.sources", cmds)
    assert stanza, "the security source must be the base's own noble-security stanza"
    assert "grep -q '^Suites: noble-security$' /tmp/apt-security/security.sources" in cmds
    sec = re.search(r'sec="([^"]*)"', cmds)
    assert sec and sec.group(1).split() == [
        "-o", "Dir::Etc::SourceList=/dev/null", "-o", "Dir::Etc::SourceParts=/tmp/apt-security"], sec
    upgrades = re.findall(r"apt-get[^;\n]*\bupgrade\b", cmds)
    assert upgrades == ["apt-get $sec -y upgrade"], (
        f"one upgrade, from the security source only (never NVIDIA's CUDA repository): {upgrades}")
    assert cmds.index("apt-get $sec update") < cmds.index("apt-get $sec -y upgrade")
    assert cmds.index("apt-get install") < cmds.index("apt-get $sec -y upgrade")


def test_runtime_stage_purges_gnupg_then_apt_and_keeps_curl():
    cmds = _commands(_runtime_stage())
    purge = re.search(r"apt-get purge -y --autoremove((?:\s|\\\n)+[^;]*);", cmds)
    assert purge, "no `apt-get purge -y --autoremove <gnupg...>` in the runtime stage"
    assert set(_words(purge.group(1))) == set(GNUPG), _words(purge.group(1))
    dpkg = re.search(r"dpkg --purge ([^;\n]*);", cmds)
    assert dpkg and _words(dpkg.group(1)) == list(APT), dpkg
    assert "--force" not in cmds, "none of the removed packages is Essential: no force flag"
    # The order: upgrade, then gnupg (with apt), then apt itself.
    assert cmds.index("-y upgrade") < purge.start() < dpkg.start()
    # curl stays: both healthchecks run it.
    install = re.search(r"apt-get install -y --no-install-recommends ([^;\n]*);", cmds)
    assert install and {"libgomp1", "curl", "ca-certificates"} <= set(_words(install.group(1))), install
    assert 'CMD curl -fs "http://localhost:${PORT}/health"' in cmds


def _job(name: str) -> dict:
    return yaml.safe_load(CI.read_text())["jobs"][name]


def _trivy_pin(job: dict) -> tuple[str, str]:
    for step in job["steps"]:
        env = step.get("env") or {}
        if "TRIVY_VERSION" in env:
            return env["TRIVY_VERSION"], env["TRIVY_SHA256"]
    raise AssertionError("no step pins TRIVY_VERSION")


def test_ci_cuda_job_reports_packages_size_and_a_trivy_scan_without_failing():
    steps = _job("llamacpp-cuda-image")["steps"]
    names = [s.get("name", "") for s in steps]
    build = next(i for i, n in enumerate(names) if n.startswith("Build the CUDA llama-server image"))
    rep = [i for i, s in enumerate(steps) if "new-findings" in (s.get("run") or "")]
    assert len(rep) == 1 and rep[0] > build, f"one report step after the build: {rep}"
    step = steps[rep[0]]
    run = step["run"]
    assert step.get("continue-on-error") is True, "the report must never fail the job"
    assert run.count("--severity HIGH,CRITICAL --ignore-unfixed") == 2, "the base and ours, the gate's flags"
    assert 'sha256sum -c -' in run, "the Trivy download must be checksum-verified"
    assert 'scripts/infra-staged.py new-findings --new "$r/base/linux-amd64.json"' in run
    assert 'scripts/infra-staged.py new-findings --new "$r/ours/linux-amd64.json"' in run
    assert run.count("dpkg-query") == 2 and "-W" in run, "package count of the base and ours"
    assert "docker image inspect -f '{{.Size}}'" in run, "image size"
    assert '"$GITHUB_STEP_SUMMARY"' in run
    # The gating step still proves the pin and the GPU-less start.
    gate = next(s for s in steps if s.get("name", "").startswith("The image starts on a runner with no GPU"))["run"]
    assert "--list-devices" in gate and "LLAMACPP_REF" in gate and "ldd" in gate


def test_ci_cuda_report_uses_the_same_trivy_pin_as_ollama_image():
    assert _trivy_pin(_job("llamacpp-cuda-image")) == _trivy_pin(_job("ollama-image"))
