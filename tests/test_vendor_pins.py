# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The pinned vendor artefacts in config/harness-kinds.json are well-formed.

The controller stages each foreign harness kind's vendor CLI to the nodes, so what it stages is pinned by version AND
sha256, written by scripts/vendor-pin.py. This holds the SHAPE offline:
every platform the fleet has is covered, digests are 64 hex, versions are
x.y.z, sources are https templates that name only known placeholders.
`vendor-pin.py --check` re-downloads and verifies the digests themselves; it
needs the internet and is deliberately not run here.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TABLE = ROOT / "config/harness-kinds.json"
COPY = ROOT / "node-agent-go/internal/reconcile/harness_kinds.json"
SCRIPT = ROOT / "scripts/vendor-pin.py"

# The platforms the fleet has, in noomesh's facts naming.
FLEET = {"linux-x86_64", "linux-aarch64", "macos-aarch64"}
OSES, ARCHES = {"linux", "macos"}, {"x86_64", "aarch64"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
FORMATS = {"tarball", "binary"}
UNPACKS = {"tgz", "zip", "none"}


def _doc() -> dict:
    return json.loads(TABLE.read_text(encoding="utf-8"))


def _kinds() -> list[dict]:
    return _doc()["kinds"]


def _check_names(where: str, names) -> None:
    if names is None:
        return
    assert set(names) == {"os", "arch"}, f"{where}: names has keys {sorted(names)}"
    assert set(names["os"]) == OSES, f"{where}: names.os must map {sorted(OSES)}"
    assert set(names["arch"]) == ARCHES, f"{where}: names.arch must map {sorted(ARCHES)}"
    for m in (names["os"], names["arch"]):
        assert all(isinstance(v, str) and v for v in m.values()), f"{where}: empty vendor name"


def _check_source(where: str, source: str, per_platform: bool) -> None:
    assert source.startswith("https://"), f"{where}: source must be https: {source}"
    used = set(PLACEHOLDER.findall(source))
    assert "version" in used, f"{where}: source does not name {{version}}"
    allowed = {"version", "os", "arch"} if per_platform else {"version"}
    assert used <= allowed, f"{where}: source names {sorted(used - allowed)}"
    if per_platform:
        assert {"os", "arch"} <= used, f"{where}: a per-platform source must name {{os}} and {{arch}}"


def _check_sha(where: str, sha: dict) -> bool:
    """True when keyed per platform; asserts the fleet is covered."""
    assert isinstance(sha, dict) and sha, f"{where}: sha256 missing"
    for k, v in sha.items():
        assert HEX64.match(v or ""), f"{where}: sha256[{k}] is not 64 lowercase hex"
    if "any" in sha:
        assert set(sha) == {"any"}, f"{where}: an `any` digest must be the only one"
        return False
    missing = FLEET - set(sha)
    assert not missing, f"{where}: no sha256 for {sorted(missing)} (the fleet has them)"
    assert set(sha) <= FLEET, f"{where}: sha256 names unknown platforms {sorted(set(sha) - FLEET)}"
    return True


def test_both_copies_are_byte_equal():
    assert TABLE.read_bytes() == COPY.read_bytes(), "re-run scripts/vendor-pin.py or copy the shipped file over"


def test_the_file_is_in_the_layout_vendor_pin_writes():
    text = TABLE.read_text(encoding="utf-8")
    assert json.dumps(json.loads(text), indent=2, ensure_ascii=False) + "\n" == text


@pytest.mark.parametrize("row", _kinds(), ids=lambda r: r["kind"])
def test_every_kind_declares_its_distribution(row):
    assert "distribution" in row, f"{row['kind']} has no distribution key (null for none)"
    d = row["distribution"]
    if row.get("cli") is None:
        assert d is None, f"{row['kind']} has no vendor CLI, so no distribution"
        return
    where = f"{row['kind']}.distribution"
    assert isinstance(d, dict), f"{row['kind']} launches {row['cli']!r} but pins no distribution"
    assert set(d) == {"format", "source", "names", "version", "sha256", "entry", "unpack"}, (
        f"{where}: keys {sorted(d)}"
    )
    assert d["format"] in FORMATS, f"{where}: format {d['format']!r}"
    assert d["unpack"] in UNPACKS, f"{where}: unpack {d['unpack']!r}"
    assert SEMVER.match(d["version"]), f"{where}: version {d['version']!r}"
    assert isinstance(d["entry"], str) and d["entry"] and not d["entry"].startswith("/"), f"{where}: entry"
    _check_names(where, d["names"])
    per_platform = _check_sha(where, d["sha256"])
    _check_source(where, d["source"], per_platform)
    if d["format"] == "binary":
        assert d["unpack"] == "none", f"{where}: a binary is not unpacked"
        assert "/" not in d["entry"], f"{where}: a binary's entry is its file name"


def test_vendor_pin_knows_every_pinned_name_and_is_not_run_in_ci():
    src = SCRIPT.read_text(encoding="utf-8")
    for k in _kinds():
        if k.get("distribution"):
            assert f'"{k["kind"]}"' in src, f"vendor-pin.py has no recipe/cross-check for {k['kind']}"
    for wf in (ROOT / ".github/workflows").glob("*.y*ml"):
        assert "vendor-pin.py" not in wf.read_text(encoding="utf-8"), (
            f"{wf.name} runs vendor-pin.py: it downloads from vendors; CI is offline by design"
        )


@pytest.mark.parametrize(
    ("args", "says"),
    [
        (["no-such-kind", "1.0.0"], "unknown kind 'no-such-kind'"),
        (["noo", "1.0.0"], "no vendor CLI"),
        (["copilot", "latest"], "is not x.y.z"),
    ],
)
def test_vendor_pin_refuses_offline_before_downloading(args, says):
    p = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 1, p.stdout + p.stderr
    assert says in p.stderr, p.stderr
