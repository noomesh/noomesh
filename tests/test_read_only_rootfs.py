# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway, worker, worker-extra and trellion run with a read-only root
filesystem (followup i132; the audit LOW "plaintext secrets persist in the
container writable layer").

The write set was measured with `docker diff` on the live controller:

  noo-gateway   /tmp/pki/** (stage_pki's copy, with the leaf KEYS),
                /tmp/noo-ca-bundle.pem, the `-unused` mount points under /tmp;
                /root and /opt changes are mount points (claude-config,
                addon-routes), not writes
  noo-worker    /tmp/pki/leaf/service.key, Python bytecode under /app/src
  noo-trellion  /tmp/pki/leaf/service.key, /tmp/.ses, /tmp/.src-overlay-unused,
                /tmp/.trellion-src-unused, the onnxruntime device id under
                ~/.cache/Microsoft, bytecode under /app/src

so each gets a size-capped tmpfs for /tmp and for HOME, bytecode is compiled at
image build and switched off at runtime, and the onnxruntime id is switched
off at the source (tests/test_no_vendor_telemetry.py).

A read-only service cannot take an `environment:`-sourced secret (compose
refuses at create): tests/test_compose_secret_files.py and
tests/test_secret_rundir.py hold the `file:` delivery.
"""

from __future__ import annotations

import re

import pytest

from tests._compose_projection import ROOT, env_of, full_projection

READ_ONLY = ("gateway", "worker", "worker-extra", "trellion")
# The nonroot uid of the images' USER, and what each service's /tmp cap and
# HOME cap must at least be (MiB): the numbers come from the measured write
# set above plus headroom, and a cap below them turns a write into ENOSPC.
HOME_UID = "65532"
MIN_TMP_MIB = {"gateway": 256, "worker": 128, "worker-extra": 128, "trellion": 512}


@pytest.fixture(scope="module")
def svcs() -> dict:
    return full_projection()["services"]


def _tmpfs(svc: dict) -> dict[str, dict[str, str]]:
    out = {}
    for t in svc.get("tmpfs") or []:
        path, _, opts = str(t).partition(":")
        out[path] = dict(o.partition("=")[::2] for o in opts.split(",") if o)
    return out


def _mib(size: str) -> int:
    m = re.fullmatch(r"(\d+)([kKmMgG]?)", size)
    assert m, f"unreadable tmpfs size {size!r}"
    n, unit = int(m.group(1)), m.group(2).lower()
    return {"": n // (1 << 20), "k": n // 1024, "m": n, "g": n * 1024}[unit]


@pytest.mark.parametrize("name", READ_ONLY)
def test_the_service_is_read_only(svcs, name):
    assert svcs[name].get("read_only") is True, (
        f"{name}: read_only is {svcs[name].get('read_only')!r}. A writable rootfs keeps every secret and "
        "key copy the service makes in the container's layer, readable from the host by `docker diff`/cp"
    )


@pytest.mark.parametrize("name", READ_ONLY)
def test_tmp_and_home_are_tmpfs_with_a_size_cap(svcs, name):
    t = _tmpfs(svcs[name])
    assert "/tmp" in t and "/home/nonroot" in t, f"{name}: tmpfs is {sorted(t)}"
    for path, opts in t.items():
        assert "size" in opts, f"{name}: tmpfs {path} has no size cap (an unbounded tmpfs is host RAM)"
    assert _mib(t["/tmp"]["size"]) >= MIN_TMP_MIB[name], f"{name}: /tmp cap {t['/tmp']['size']} is below the measured need"
    assert t["/tmp"].get("mode") == "1777", f"{name}: /tmp must be sticky and world-writable, as /tmp is"
    home = t["/home/nonroot"]
    assert home.get("uid") == HOME_UID and home.get("gid") == HOME_UID and home.get("mode") == "0700", (
        f"{name}: HOME is {home}: it must belong to the image's nonroot user and be private"
    )


def test_worker_and_extra_have_the_same_tmpfs(svcs):
    assert _tmpfs(svcs["worker"]) == _tmpfs(svcs["worker-extra"])


@pytest.mark.parametrize("name", ["worker", "worker-extra", "trellion"])
def test_python_bytecode_is_not_written_at_runtime(svcs, name):
    assert env_of(svcs[name]).get("PYTHONDONTWRITEBYTECODE") == "1"


@pytest.mark.parametrize("dockerfile", ["docker/Dockerfile.worker", "docker/Dockerfile.trellion"])
def test_the_image_compiles_the_sources_it_will_not_be_able_to_write_back(dockerfile):
    text = (ROOT / dockerfile).read_text()
    lines = text.splitlines()
    idx = next((i for i, ln in enumerate(lines) if re.search(r"compileall\b.*\s/app/src", ln)), None)
    assert idx is not None, f"{dockerfile}: no `python -m compileall /app/src`"
    user = next(i for i, ln in enumerate(lines) if ln.startswith("USER nonroot"))
    copy = next(i for i, ln in enumerate(lines) if re.match(r"COPY src\b", ln))
    assert copy < idx < user, f"{dockerfile}: compile after COPY src and before USER nonroot (as root, then chown)"
    assert "chown -R nonroot:nonroot /app" in "\n".join(lines[idx : idx + 2])


def test_no_read_only_service_takes_an_environment_secret():
    """compose refuses `environment:`-sourced secrets on a read-only service
    ("`file` is the sole supported option"); the projection of every
    top-level secret must be a file."""
    p = full_projection()
    read_only = {n for n, s in p["services"].items() if s.get("read_only")}
    assert set(READ_ONLY) <= read_only
    env_sourced = {k for k, v in (p.get("secrets") or {}).items() if v.get("environment")}
    taken = {s["source"] if isinstance(s, dict) else s for n in read_only for s in (p["services"][n].get("secrets") or [])}
    assert not (taken & env_sourced), f"read-only services take environment-sourced secrets: {sorted(taken & env_sourced)}"


def test_the_dev_source_overlays_stay_readable_mounts(svcs):
    """Dev mode bind-mounts ./src over /app/src (trellion) and the static
    dir (gateway): bind mounts are unaffected by a read-only rootfs, and the
    overlay hides the baked bytecode, so nothing writes back."""
    vols = [v for v in svcs["trellion"].get("volumes") or [] if isinstance(v, dict)]
    assert any(str(v.get("target")) in ("${NOO_SRC_OVERLAY_DEST:-/app/src}", "/app/src") and v.get("read_only") for v in vols)
    # the mounted config, prompts and the host spool are the writable paths the gateway needs
    gw = {v["target"]: v for v in svcs["gateway"].get("volumes") or [] if isinstance(v, dict)}
    for t in ("/app/noomesh.yaml", "/app/prompts", "/data", "/var/run/noo-spool"):
        assert t in gw and not gw[t].get("read_only"), f"gateway {t} must stay writable"
