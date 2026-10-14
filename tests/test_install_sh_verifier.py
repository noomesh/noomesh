# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""install.sh's release-signature verifier without python3.

rc.3 rehearsal: a host with no python3 and no installed noo printed
"release signature INVALID" -- the wrong cause. The function now returns 2
for "no verifier at all" (the caller prints one honest line), and an
OpenSSL 3 host verifies Ed25519 itself. The signature is minted here with a
throwaway key against the pinned-key slot, so no network is needed.
"""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "noo-cli" / "install.sh"


def _openssl3() -> bool:
    exe = shutil.which("openssl")
    if not exe:
        return False
    out = subprocess.run([exe, "version"], capture_output=True, text=True).stdout
    return out.startswith("OpenSSL ") and out.split()[1][0] in "3456789"


def _fn_source(pubkey_hex: str) -> str:
    text = INSTALL.read_text()
    i = text.index("err() {")
    j = text.index("# ---- detect platform")
    return f'RELEASE_PUBKEYS="{pubkey_hex}"\nSIG_PREFIX="noo-sig1."\n' + text[i:j]


def _bin(tmp: Path, tools: list[str]) -> Path:
    b = tmp / "bin"
    b.mkdir()
    for t in tools:
        p = shutil.which(t)
        if p:
            (b / t).symlink_to(p)
    return b


def _verify(tmp: Path, pub: str, manifest: Path, sig: Path, tools: list[str]) -> subprocess.CompletedProcess[str]:
    b = _bin(tmp, tools)
    (tmp / "fn.sh").write_text(_fn_source(pub))
    sh = shutil.which("sh")
    return subprocess.run(
        [sh, "-c", f'. "{tmp}/fn.sh"; verify_release_sig "{manifest}" "{sig}"'],
        env={"PATH": str(b)}, capture_output=True, text=True,
    )


BASE = ["openssl", "tr", "printf", "wc", "mktemp", "rm", "cat"]


@pytest.fixture
def signed(tmp_path: Path):
    if not _openssl3():
        pytest.skip("needs OpenSSL 3 to mint a test signature")
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True, capture_output=True)
    der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    pub = der[-32:].hex()
    mf = tmp_path / "sha256sums.txt"
    mf.write_bytes(b"abc  noo-x86_64\n")
    raw = subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(mf)],
                         check=True, capture_output=True).stdout
    sig = tmp_path / "sha256sums.txt.sig"
    sig.write_text("noo-sig1." + base64.urlsafe_b64encode(raw).decode().rstrip("=") + "\n")
    return pub, mf, sig


def test_openssl_verifies_without_python3(tmp_path: Path, signed) -> None:
    pub, mf, sig = signed
    r = _verify(tmp_path, pub, mf, sig, BASE)
    assert r.returncode == 0, r.stderr


def test_openssl_rejects_a_tampered_manifest(tmp_path: Path, signed) -> None:
    pub, mf, sig = signed
    mf.write_bytes(mf.read_bytes() + b"x\n")
    r = _verify(tmp_path, pub, mf, sig, BASE)
    assert r.returncode == 1, r.stderr


def test_openssl_rejects_a_foreign_key(tmp_path: Path, signed) -> None:
    _, mf, sig = signed
    r = _verify(tmp_path, "13be2244d5b91b1d5c29dfffd94a3817cb774c906785cf700e10a86d7be62d43", mf, sig, BASE)
    assert r.returncode == 1


def test_no_verifier_is_its_own_outcome_not_an_invalid_signature(tmp_path: Path, signed) -> None:
    pub, mf, sig = signed
    r = _verify(tmp_path, pub, mf, sig, ["tr", "cat", "rm"])  # no python3, no openssl, no noo
    assert r.returncode == 2, r.stderr


def test_the_caller_reports_no_verifier_not_invalid() -> None:
    text = INSTALL.read_text()
    assert 'err "no verifier available: install python3" 1' in text
    i = text.index('[ "$_vrc" = 2 ]')
    assert i < text.index("release signature INVALID"), "the no-verifier case must be handled first"
