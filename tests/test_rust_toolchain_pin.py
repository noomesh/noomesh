# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The Rust toolchain is pinned, and lint runs before the long Rust steps (i5).

noomesh-pv #1000 passed clippy locally (1.97) and failed it in CI (1.99):
the lint set moves with the toolchain. So:

  * every crate CI builds carries a rust-toolchain.toml, all naming the SAME
    exact version, with the clippy component;
  * in the rust-gateway and noo-cli jobs the clippy step precedes every
    cargo check/test/build step, so a lint failure fails the job early.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
CRATES = ["gateway-rust", "noo-cli"]
RUST_JOBS = ["rust-gateway", "noo-cli"]


def _pin(crate: str) -> dict:
    path = REPO / crate / "rust-toolchain.toml"
    assert path.is_file(), f"{crate}/rust-toolchain.toml is missing"
    return tomllib.loads(path.read_text())["toolchain"]


@pytest.mark.parametrize("crate", CRATES)
def test_each_crate_pins_an_exact_version_with_clippy(crate):
    t = _pin(crate)
    assert re.fullmatch(r"\d+\.\d+\.\d+", t["channel"]), (
        f"{crate}: channel must be an exact x.y.z, not {t['channel']!r}"
    )
    assert "clippy" in t.get("components", [])


def test_all_crates_name_the_same_version():
    versions = {c: _pin(c)["channel"] for c in CRATES}
    assert len(set(versions.values())) == 1, versions


def test_every_cargo_manifest_crate_ci_builds_is_pinned():
    # A crate that CI lints/tests must be in CRATES: catch a new one.
    ci = (REPO / ".github/workflows/ci.yml").read_text()
    for crate in re.findall(r'CARGO_DOCKER_CRATE="\$PWD/([\w.-]+)"', ci):
        assert crate in CRATES, f"ci.yml builds {crate}; add it to CRATES and pin it"


def _steps(job: str) -> list[dict]:
    doc = yaml.safe_load((REPO / ".github/workflows/ci.yml").read_text())
    return doc["jobs"][job]["steps"]


@pytest.mark.parametrize("job", RUST_JOBS)
def test_clippy_precedes_every_other_cargo_step(job):
    steps = _steps(job)
    cargo = [
        (i, s) for i, s in enumerate(steps)
        if "cargo-docker.sh" in s.get("run", "") and "scripts/cargo-docker.sh clean" not in s["run"]
    ]
    clippy = [i for i, s in cargo if re.search(r"cargo-docker\.sh clippy\b", s["run"])]
    assert clippy, f"{job}: no clippy step"
    assert "-D warnings" in steps[clippy[0]]["run"]
    earlier = [s.get("name") for i, s in cargo if i < clippy[0]]
    assert not earlier, f"{job}: cargo steps run before clippy: {earlier}"
