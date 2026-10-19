# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The shipped Python image installs from a hash-locked file, not from ranges.

`pyproject.toml` declares `>=` ranges, so an unlocked `uv pip install -e .[...]`
resolves whatever PyPI serves on build day: a release published after review
(or a hijacked one) enters the image with no hash to refuse it. The shipped
install set is `docker/core-lock/requirements.txt`, installed with `--require-hashes`.
This guard fails if Dockerfile.deps-core goes back to resolving from ranges,
if the lock loses its hashes, or if the extras the Dockerfile used to name and
the extras the lock was compiled for drift apart.

The ML tier (`docker/Dockerfile.deps-base`: trellion, rag, voice, torch's
index) is held to the same rule by `docker/ml-lock/requirements.txt`: the
third-party set installs with `--require-hashes`, the three local packages
(trellion and trellion-protocols from their pinned build contexts, the gateway
client from this tree) install `--no-deps --no-build-isolation`, and the lock
holds deps-core's pins at the same versions.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker" / "Dockerfile.deps-core"
LOCK = ROOT / "docker" / "core-lock" / "requirements.txt"


def _install_commands() -> list[str]:
    """Each RUN instruction of the Dockerfile that installs Python packages,
    with line continuations joined."""
    text = DOCKERFILE.read_text().replace("\\\n", " ")
    runs = [l for l in text.splitlines() if l.startswith("RUN ")]
    found = [r for r in runs if "pip install" in r]
    assert found, "parse found no `pip install` RUN in Dockerfile.deps-core"
    return found


def test_dockerfile_installs_from_the_hash_lock() -> None:
    cmds = _install_commands()
    locked = [c for c in cmds if "-r /tmp/requirements-core.txt" in c]
    assert locked, "deps-core must install third-party packages from the lock"
    for c in locked:
        assert "--require-hashes" in c, f"lock install without --require-hashes: {c}"
    # Anything else that installs must not resolve from ranges: only the
    # project itself, editable, with --no-deps, is allowed.
    for c in cmds:
        for part in re.split(r"&&|;", c):
            if "pip install" not in part or "-r /tmp/requirements-core.txt" in part:
                continue
            assert "--no-deps" in part and re.search(r"-e \.(\s|$)", part), (
                f"unlocked install in deps-core resolves from pyproject ranges: {part.strip()}"
            )
            assert "--no-build-isolation" in part, (
                f"the project's build backend resolves from PyPI unhashed (no --no-build-isolation): {part.strip()}"
            )
            assert "[" not in part, f"extras in the unlocked project install: {part.strip()}"


def test_dockerfile_copies_the_lock_before_installing() -> None:
    text = DOCKERFILE.read_text()
    copy = text.find("COPY docker/core-lock/requirements.txt /tmp/requirements-core.txt")
    install = text.find("-r /tmp/requirements-core.txt")
    assert copy != -1 and install != -1 and copy < install


def test_every_pin_in_the_lock_carries_hashes() -> None:
    text = LOCK.read_text().replace("\\\n", " ")
    pins = [
        l for l in text.splitlines()
        if l and not l.startswith(("#", " ")) and "==" in l
    ]
    assert len(pins) > 20, f"lock parse found only {len(pins)} pins"
    for l in pins:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", l), f"pin without a sha256 hash: {l[:60]}"
    assert not re.search(r"^\s*(-e|git\+|https?://)", LOCK.read_text(), re.M), (
        "lock must contain registry pins only"
    )


def test_lock_header_extras_cover_the_pyproject_extras_the_image_needs() -> None:
    header = "\n".join(l for l in LOCK.read_text().splitlines() if l.startswith("#"))
    for extra in ("web", "cache", "feedback", "pgvector", "mcp"):
        assert f"--extra {extra}" in header, f"lock header lost --extra {extra}"
    # ML extras belong to Dockerfile.deps-base, never the core lock.
    for extra in ("trellion", "rag", "voice"):
        assert f"--extra {extra}" not in header


# ── the ML tier (Dockerfile.deps-base) ──────────────────────────────────────

DEPS_BASE = ROOT / "docker" / "Dockerfile.deps-base"
ML_LOCK = ROOT / "docker" / "ml-lock" / "requirements.txt"


def _pins(path: Path) -> dict[str, str]:
    text = path.read_text().replace("\\\n", " ")
    out = {}
    for l in text.splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==(\S+)", l)
        if m:
            out[m.group(1).lower().replace("_", "-")] = m.group(2)
    return out


def _base_runs() -> list[str]:
    text = DEPS_BASE.read_text().replace("\\\n", " ")
    return [l for l in text.splitlines() if l.startswith("RUN ") and "pip install" in l]


def test_deps_base_installs_from_its_hash_lock() -> None:
    runs = _base_runs()
    assert runs, "parse found no `pip install` RUN in Dockerfile.deps-base"
    text = DEPS_BASE.read_text()
    copy = text.find("COPY docker/ml-lock/requirements.txt /tmp/requirements-ml.txt")
    assert copy != -1 and copy < text.find("-r /tmp/requirements-ml.txt"), "lock must be copied before it is used"
    locked = [r for r in runs if "-r /tmp/requirements-ml.txt" in r]
    assert locked, "deps-base must install third-party packages from docker/ml-lock/requirements.txt"
    for r in locked:
        assert "--require-hashes" in r, f"lock install without --require-hashes: {r}"
    # Every other install in the image is a LOCAL package, with no dependency
    # resolution and no build-backend fetch: that is what keeps the ranges in
    # pyproject.toml and in trellion's own metadata out of the build.
    for r in runs:
        for part in re.split(r"&&|;", r):
            if "pip install" not in part or "-r /tmp/requirements-ml.txt" in part:
                continue
            assert "--no-deps" in part, f"unlocked dependency resolution in deps-base: {part.strip()}"
            assert "--no-build-isolation" in part, (
                f"build backend resolved unhashed (no --no-build-isolation): {part.strip()}"
            )
            for arg in part.split("pip install", 1)[1].split():
                assert arg.startswith(("-", "/tmp/")), f"deps-base installs a non-local package: {arg}"
            assert "[" not in part, f"extras on a --no-deps install do nothing: {part.strip()}"
    last = runs[-1]
    assert "pip check" in last, "a stale lock must fail the build (uv pip check), not ship an import error"


def test_deps_base_resolves_nothing_from_a_git_url_or_overrides() -> None:
    text = DEPS_BASE.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "uv-overrides" not in code and "--overrides" not in code
    assert "git+" not in code


def test_every_pin_in_the_ml_lock_carries_hashes() -> None:
    text = ML_LOCK.read_text().replace("\\\n", " ")
    pins = [l for l in text.splitlines() if l and not l.startswith(("#", " ")) and "==" in l]
    assert len(pins) > 100, f"ml lock parse found only {len(pins)} pins"
    for l in pins:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", l), f"pin without a sha256 hash: {l[:60]}"
    assert not re.search(r"^\s*(-e|git\+|https?://|\S+ @ )", ML_LOCK.read_text(), re.M), (
        "ml lock must contain registry pins only (trellion & co. install from build contexts)"
    )


def test_the_ml_lock_agrees_with_the_core_lock() -> None:
    """Installing the ML lock over deps-core must not move a package in the
    layer below, and Dependabot bumping one lock alone would."""
    core, ml = _pins(LOCK), _pins(ML_LOCK)
    assert len(core) > 20 and len(ml) > len(core)
    drift = {k: (v, ml[k]) for k, v in core.items() if k in ml and ml[k] != v}
    assert not drift, f"ml-lock disagrees with core-lock (regenerate both together): {drift}"
    assert set(core) <= set(ml), f"ml-lock lost core packages: {sorted(set(core) - set(ml))}"


def test_the_ml_lock_carries_the_build_backends_and_no_local_packages() -> None:
    """The local packages build with --no-build-isolation, so their backends
    must be installed from the lock, hashed; and the packages that come from
    build contexts must not be in it."""
    ml = _pins(ML_LOCK)
    for backend in ("hatchling", "setuptools"):
        assert backend in ml, f"{backend} builds a local package and must be in the lock"
    for local in ("trellion", "trellion-protocols", "noo-gateway-client", "noomesh"):
        assert local not in ml, f"{local} comes from a build context, not the lock"


def test_the_ml_lock_is_cpu_only() -> None:
    """Nothing built on deps-base has a GPU: a CUDA torch (or the nvidia-*/
    triton wheels it drags in) is ~4.5GB that can never run. torch may enter
    the tree later; it must then be the +cpu build from the CPU index."""
    ml = _pins(ML_LOCK)
    gpu = sorted(k for k in ml if k.startswith("nvidia-") or k in ("triton", "cuda-toolkit"))
    assert not gpu, f"GPU wheels in the ML lock: {gpu}"
    if "torch" in ml:
        assert "+cpu" in ml["torch"] or "https://download.pytorch.org/whl/cpu" in ML_LOCK.read_text(), (
            "torch is in the lock without the CPU index"
        )
        assert "+cu" not in ml["torch"]
    header = "\n".join(l for l in ML_LOCK.read_text().splitlines() if l.startswith("#"))
    assert "scripts/regen-ml-lock.sh" in header


def test_the_regen_script_compiles_the_extras_the_image_needs() -> None:
    script = (ROOT / "scripts" / "regen-ml-lock.sh").read_text()
    for extra in ("trellion", "web", "cache", "feedback", "pgvector", "mcp", "rag", "voice"):
        assert f"--extra {extra}" in script, f"regen-ml-lock.sh lost --extra {extra}"
    assert "--generate-hashes" in script and "--constraints docker/core-lock/requirements.txt" in script
    assert "https://download.pytorch.org/whl/cpu" in script


def test_dependabot_watches_the_ml_lock() -> None:
    import yaml

    doc = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    dirs = {u["directory"] for u in doc["updates"] if u["package-ecosystem"] == "pip"}
    assert "/docker/ml-lock" in dirs and "/docker/core-lock" in dirs


# ── build backends are hashed, in every lock whose image builds a local package ──

PYPROJECT = ROOT / "pyproject.toml"
BACKEND_IN = ROOT / "docker" / "core-lock" / "build-backends.in"


def _build_system_requires() -> list[str]:
    text = PYPROJECT.read_text()
    m = re.search(r"^\[build-system\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    assert m, "pyproject.toml has no [build-system] table"
    r = re.search(r"^requires\s*=\s*\[(.*?)\]", m.group(1), re.M | re.S)
    assert r, "[build-system] has no requires"
    return re.findall(r"[\"']([^\"']+)[\"']", r.group(1))


def _lock_block(path: Path, name: str) -> str:
    """The pin line plus its hashes for `name`, or ''."""
    text = path.read_text().replace("\\\n", " ")
    for l in text.splitlines():
        if re.match(rf"^{re.escape(name)}==", l, re.I):
            return l
    return ""


def test_the_core_lock_pins_and_hashes_the_projects_build_backend() -> None:
    """deps-core builds the project --no-build-isolation, so pyproject's
    [build-system] backend must be installed from the hashed lock. Without it
    the build resolved setuptools from PyPI with no hash."""
    requires = _build_system_requires()
    assert requires, "pyproject.toml lost [build-system].requires"
    for req in requires:
        name = re.split(r"[<>=!~\[ ;]", req, 1)[0].lower().replace("_", "-")
        line = _lock_block(LOCK, name)
        assert line, f"build backend {name} (pyproject [build-system]) is not pinned in core-lock"
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", line), f"build backend {name} pinned without a hash"
        assert name in BACKEND_IN.read_text().lower(), f"{name} missing from core-lock/build-backends.in (regen input)"


def test_no_dockerfile_builds_a_local_package_with_an_isolated_backend() -> None:
    """Every image that installs a local package (an editable `.`, a /tmp
    context, a path) must pass --no-build-isolation; the shipped Dockerfiles
    are the two layered ones. (The root Dockerfile is the deliberate unlocked
    resolution gate for CI and is exempt.)"""
    for df in (DOCKERFILE, DEPS_BASE):
        text = df.read_text().replace("\\\n", " ")
        for l in text.splitlines():
            if not l.startswith("RUN ") or "pip install" not in l:
                continue
            for part in re.split(r"&&|;", l):
                if "pip install" not in part or "-r /tmp/requirements" in part:
                    continue
                assert "--no-build-isolation" in part, f"{df.name}: isolated build resolves its backend unhashed: {part.strip()}"


def test_the_backend_is_hashed_in_the_ml_lock_at_the_core_version() -> None:
    ml, core = _pins(ML_LOCK), _pins(LOCK)
    for req in _build_system_requires():
        name = re.split(r"[<>=!~\[ ;]", req, 1)[0].lower().replace("_", "-")
        assert name in ml and ml[name] == core.get(name), f"{name}: ml {ml.get(name)} vs core {core.get(name)}"
