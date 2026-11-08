# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on's node workload door leaf travels the rail (i300 section 10.1 A1).

Kinds `svc-addon-<addon>-<workload>.crt|.key` are an OPEN set, so the three
allow-lists (scripts/noo-apply.sh, scripts/sign-bundle.sh, node_fetch.rs)
judge them by SHAPE rather than by a listed name. This pins, in tmp dirs and
with the real scripts:

  - noo-apply.sh installs a valid pair to services/addon-<a>-<w>/service.{crt,key}
    (key 0600, cert 0644, dir 0755) and a second identical apply is "unchanged";
  - it REFUSES (non-zero, nothing installed) a malformed name or a half pair;
  - sign-bundle.sh signs a valid kind and refuses an invalid one;
  - the Rust constants the scripts mirror (the floor, the 51-char cap) agree.

Not covered: a real apply as root (the install/mv/stat stubs of
test_apply_unchanged_configs.py stand in for it).
"""

from __future__ import annotations

import re
import stat as statmod
import subprocess
from pathlib import Path

import pytest

from tests.test_apply_unchanged_configs import APPLIER, LINES, PRELUDE, delimited

REPO = Path(__file__).resolve().parents[1]
SIGN = REPO / "scripts" / "sign-bundle.sh"
LEAVES_RS = (REPO / "noo-cli/src/commands/node_leaves.rs").read_text()
NODE = "node1"
VALID = "svc-addon-rhaddon-worker"


def _lift_addon_loop() -> str:
    start = next(i for i, l in enumerate(LINES) if l.startswith("for _asvc in $(for _af in "))
    for j in range(start + 1, len(LINES)):
        if LINES[j] == "done":
            return "\n".join(LINES[start: j + 1]) + "\n"
    raise AssertionError("no end of the svc-addon install loop")


ADDON_LOOP = _lift_addon_loop()
KIND_FN = delimited("addon_leaf_kind")


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture()
def pki_material(tmp_path: Path) -> Path:
    """A throwaway CA and one leaf signed by it, all under tmp_path/ssl."""
    d = tmp_path / "ssl"
    d.mkdir()
    _openssl("genrsa", "-out", "ca.key", "2048", cwd=d)
    _openssl("req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=test-ca", "-days", "2", "-out", "ca.crt", cwd=d)
    _openssl("genrsa", "-out", "leaf.key", "2048", cwd=d)
    _openssl("req", "-new", "-key", "leaf.key", "-subj", "/CN=addon-rhaddon-worker", "-out", "leaf.csr", cwd=d)
    _openssl("x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
             "-days", "2", "-out", "leaf.crt", cwd=d)
    return d


def _apply(root: Path, files: dict[str, bytes], ca: Path | None) -> subprocess.CompletedProcess:
    work = root / "work"
    subprocess.run(["rm", "-rf", str(work)], check=True)
    (work / "files").mkdir(parents=True)
    for name, data in files.items():
        (work / "files" / name).write_bytes(data)
    pki = root / "pki"
    pki.mkdir(exist_ok=True)
    if ca is not None:
        (pki / "ca.crt").write_bytes((ca / "ca.crt").read_bytes())
    script = f'''ROOT="{root}"
{PRELUDE}
WORK="{work}"; PKI="{pki}"; NODE_ID="{NODE}"
applied=""
{KIND_FN}
{delimited("config_unchanged")}
{ADDON_LOOP}
echo "applied=$applied"
'''
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def _pair(ca_dir: Path, stem: str) -> dict[str, bytes]:
    return {f"{stem}.crt": (ca_dir / "leaf.crt").read_bytes(), f"{stem}.key": (ca_dir / "leaf.key").read_bytes()}


def test_noo_apply_installs_a_valid_addon_leaf_with_the_static_modes(tmp_path: Path, pki_material: Path) -> None:
    r = _apply(tmp_path, _pair(pki_material, VALID), pki_material)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "applied= svc-addon-rhaddon-worker" in r.stdout, r.stdout
    d = tmp_path / "pki/services/addon-rhaddon-worker"
    assert (d / "service.crt").read_bytes() == (pki_material / "leaf.crt").read_bytes()
    assert (d / "service.key").read_bytes() == (pki_material / "leaf.key").read_bytes()
    mode = lambda p: statmod.S_IMODE(p.stat().st_mode)
    assert mode(d / "service.key") == 0o600
    assert mode(d / "service.crt") == 0o644
    assert not list(d.glob(".service.*.next")), "a temp file was left behind"
    # Identical second apply installs nothing.
    again = _apply(tmp_path, _pair(pki_material, VALID), pki_material)
    assert again.returncode == 0 and "svc-addon-rhaddon-worker=unchanged" in again.stdout, again.stdout


def test_noo_apply_never_deletes_a_leaf_the_bundle_does_not_carry(tmp_path: Path, pki_material: Path) -> None:
    assert _apply(tmp_path, _pair(pki_material, VALID), pki_material).returncode == 0
    r = _apply(tmp_path, {}, pki_material)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "pki/services/addon-rhaddon-worker/service.crt").is_file()


@pytest.mark.parametrize("stem", ["svc-addon-Bad", "svc-addon-a_b-w", "svc-addon-a-", "svc-addon-a.b", "svc-addon--x"])
def test_noo_apply_refuses_a_malformed_addon_leaf_and_installs_nothing(
    tmp_path: Path, pki_material: Path, stem: str
) -> None:
    r = _apply(tmp_path, _pair(pki_material, stem), pki_material)
    assert r.returncode != 0, r.stdout
    assert "well-formed" in r.stderr, r.stderr
    assert not (tmp_path / "pki/services").exists() or not any((tmp_path / "pki/services").iterdir())


def test_noo_apply_refuses_a_half_addon_pair(tmp_path: Path, pki_material: Path) -> None:
    r = _apply(tmp_path, {f"{VALID}.crt": (pki_material / "leaf.crt").read_bytes()}, pki_material)
    assert r.returncode != 0 and "half a leaf" in r.stderr, r.stderr
    assert not (tmp_path / "pki/services").exists() or not any((tmp_path / "pki/services").iterdir())


def test_noo_apply_refuses_a_cert_that_does_not_chain_to_the_trusted_ca(tmp_path: Path, pki_material: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    _openssl("genrsa", "-out", "ca.key", "2048", cwd=other)
    _openssl("req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=other", "-days", "2", "-out", "ca.crt", cwd=other)
    r = _apply(tmp_path, _pair(pki_material, VALID), other)
    assert r.returncode != 0 and "does not verify" in r.stderr, r.stderr


KIND_CASES = [
    (f"{VALID}.crt", True), (f"{VALID}.key", True), ("svc-addon-a-b.crt", True),
    ("svc-addon-" + "a" * 51 + ".crt", True), ("svc-addon-" + "a" * 52 + ".crt", False),
    ("svc-addon-Bad.crt", False), ("svc-addon-a_b-w.crt", False), ("svc-addon-../x.crt", False),
    ("svc-addon-a/b.crt", False), ("svc-addon-.crt", False), ("svc-addon-a.b.key", False),
    ("svc-addon-a-.key", False), ("svc-vllm.crt", False), ("svc-addon-a-b.pem", False),
    ("svc-addon--x.crt", False), ("svc-addon--.key", False),
]


@pytest.mark.parametrize("kind,ok", KIND_CASES)
def test_the_apply_kind_rule(kind: str, ok: bool) -> None:
    r = subprocess.run(["bash", "-c", f'{KIND_FN}\naddon_leaf_kind_ok "$1"', "x", kind], capture_output=True, text=True)
    assert (r.returncode == 0) is ok, f"{kind}: rc={r.returncode} {r.stderr}"


def _sign(stage: Path, key: Path, out: Path) -> subprocess.CompletedProcess:
    with out.open("wb") as fh:
        return subprocess.run(["bash", str(SIGN), str(stage), NODE, str(key)], stdout=fh, stderr=subprocess.PIPE, text=False)


@pytest.fixture()
def signing_key(tmp_path: Path) -> Path:
    d = tmp_path / "sk"
    d.mkdir()
    _openssl("genrsa", "-out", "signing.key", "2048", cwd=d)
    return d / "signing.key"


def test_sign_bundle_accepts_a_valid_addon_leaf_kind(tmp_path: Path, signing_key: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / f"{VALID}.crt").write_bytes(b"CRT\n")
    (stage / f"{VALID}.key").write_bytes(b"KEY\n")
    r = _sign(stage, signing_key, tmp_path / "bundle.tar")
    assert r.returncode == 0, r.stderr.decode()
    listing = subprocess.run(["tar", "-tf", str(tmp_path / "bundle.tar")], capture_output=True, text=True, check=True).stdout
    assert f"files/{VALID}.crt" in listing and f"files/{VALID}.key" in listing, listing


@pytest.mark.parametrize("bad", ["svc-addon-Bad.crt", "svc-addon-a_b-w.crt", "svc-addon-a-.key", "svc-addon-x.pem"])
def test_sign_bundle_refuses_an_invalid_addon_leaf_kind(tmp_path: Path, signing_key: Path, bad: str) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / bad).write_bytes(b"X\n")
    r = _sign(stage, signing_key, tmp_path / "bundle.tar")
    assert r.returncode == 65 and b"is not a bundle kind" in r.stderr, r.stderr.decode()


def test_the_rust_constants_match_what_the_scripts_enforce() -> None:
    assert "pub const APPLIER_ADDON_LEAVES_FLOOR: (u32, u32, u32) = (0, 6, 18);" in LEAVES_RS
    assert "pub const ADDON_DOOR_NAME_MAX: usize = 51;" in LEAVES_RS
    for text in (APPLIER, SIGN.read_text()):
        assert '[ "${#_alk}" -le 57 ]' in text and '*[!a-z0-9-]*|-*|*-' in text
    # the static allow-lists stay plain string sets (no addon names listed)
    m = re.search(r'^KNOWN_KINDS="([^"]*)"$', APPLIER, re.M)
    assert m and "svc-addon" not in m.group(1)
