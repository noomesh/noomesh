# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""packages/noo-gateway-client: its tests run in CI, and it stays a package
of its own — httpx only, no `noomesh`, Apache-2.0.

The client is what trellion, trellion-intel and evolve will import instead
of their three hand-rolled copies. It lives in this
monorepo so it versions with the gateway whose contract it encodes, and
these guards keep it importable from an image that carries no core at all
(evolve's is `python:3.12-slim` + `pip install .`) and cleanly licensed apart
from core (trellion-intel is proprietary and must import it).
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packages" / "noo-gateway-client"
SRC = PKG / "src" / "noo_gateway"

# stdlib modules the package may import; anything else must be httpx or itself.
_STDLIB_OK = {
    "asyncio", "collections", "dataclasses", "hashlib", "hmac", "logging", "os", "ssl",
    "threading", "time", "typing", "__future__",
}


def test_the_packages_own_suite_passes() -> None:
    """Run the package's pytest as CI would, and insist it collected tests."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(PKG), "-q", "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=ROOT, timeout=300,
    )
    tail = "\n".join(proc.stdout.splitlines()[-15:]) + "\n" + proc.stderr[-2000:]
    assert proc.returncode == 0, f"noo-gateway-client tests failed:\n{tail}"
    last = [ln for ln in proc.stdout.splitlines() if " passed" in ln]
    assert last, f"no 'passed' summary — nothing collected?\n{tail}"
    n = int(last[-1].split(" passed")[0].split()[-1])
    assert n >= 40, f"only {n} tests collected; the suite is {last[-1]!r}"


def test_depends_on_httpx_and_nothing_else() -> None:
    meta = tomllib.loads((PKG / "pyproject.toml").read_text())
    deps = [d.split()[0].split(">")[0].split("<")[0].split("=")[0].strip() for d in meta["project"]["dependencies"]]
    assert deps == ["httpx"], deps
    assert "optional-dependencies" not in meta["project"], "no extras: the package is one thing"
    assert meta["project"]["name"] == "noo-gateway-client"
    assert meta["project"]["license"] == "Apache-2.0"
    repo = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["requires-python"]
    assert meta["project"]["requires-python"] == repo, "the package pins the same interpreter as the repo"


def test_imports_nothing_from_noomesh_or_beyond_httpx() -> None:
    files = sorted(SRC.glob("*.py"))
    assert len(files) >= 6, [f.name for f in files]
    for f in files:
        tree = ast.parse(f.read_text(), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:  # relative: inside the package
                    continue
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                assert top != "noomesh", f"{f.name} imports noomesh: {name}"
                assert top in _STDLIB_OK or top in {"httpx", "noo_gateway"}, (
                    f"{f.name} imports {name!r}; the package depends on httpx only"
                )


def test_ships_typed_and_licensed() -> None:
    assert (SRC / "py.typed").exists()
    assert (PKG / "LICENSE").read_text().lstrip().startswith("Apache License")
    assert "Apache-2.0" in (PKG / "README.md").read_text()


def test_the_license_metadata_is_what_current_setuptools_accepts() -> None:
    """stack-v0.2.77's deps-base died on `project.license must be string`.

    With `license-files` set, setuptools >= 77 wants an SPDX string and refuses
    a `License ::` classifier beside it. Dev CI never builds this wheel (only
    the release's image build does), so the rule is held here statically.
    """
    meta = tomllib.loads((PKG / "pyproject.toml").read_text())
    assert isinstance(meta["project"]["license"], str), "an SPDX string, not {text = ...}"
    assert not [c for c in meta["project"].get("classifiers", []) if c.startswith("License ::")]
    req = meta["build-system"]["requires"]
    assert any(r.replace(" ", "").startswith("setuptools>=") and
               tuple(int(x) for x in r.split(">=")[1].split(".")[:1]) >= (77,) for r in req), req


def test_the_wheel_builds() -> None:
    """Build it the way the image does: an isolated build, current setuptools."""
    import tempfile
    with tempfile.TemporaryDirectory() as out:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", out, str(PKG)],
            capture_output=True, text=True, timeout=300,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert list(Path(out).glob("noo_gateway_client-*.whl"))


def test_nothing_public_returns_a_header_dict() -> None:
    """The rule an add-on's one-door test can then hold."""
    init = ast.parse((SRC / "__init__.py").read_text())
    exported = None
    for node in init.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "__all__" for t in node.targets):
            exported = [ast.literal_eval(e) for e in node.value.elts]  # type: ignore[attr-defined]
    assert exported, "__all__ missing"
    for name in exported:
        assert "header" not in name.lower(), f"{name} sounds like a header helper"
    src = "\n".join(f.read_text() for f in SRC.glob("*.py"))
    assert "def gateway_auth_header" not in src
    assert "def internal_gateway_headers" not in src


def test_the_images_install_it() -> None:
    """deps-base (trellion, trellion-intel FROM it) installs the package from
    the build context; the evolve add-on (built by its own repo) may take it as a named context
    for the evolve add-on's Dockerfile to `COPY --from=gwclient`."""
    deps_base = (ROOT / "docker" / "Dockerfile.deps-base").read_text()
    assert "COPY packages/noo-gateway-client /tmp/noo-gateway-client" in deps_base
    assert "noo-gateway-client @ file:///tmp/noo-gateway-client" in deps_base
    assert "/tmp/noo-gateway-client" in deps_base.split("uv pip install --system")[-1]
    # The evolve image is built by the add-on's own release workflow
    # (2026-10-11), not here, so this release no longer passes the `gwclient`
    # named context. The Dockerfile has never used it; that workflow refuses
    # to build if one ever does.
    release = (ROOT / ".github" / "workflows" / "images-release.yml").read_text()
    assert "gwclient" not in release
    ignore = (ROOT / ".dockerignore").read_text()
    assert "packages" not in ignore, "the build context must carry packages/"
