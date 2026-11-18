# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/release-vouch-previous.py (i908): every release vouches for its
previous final, by digest, from that final's own signed lists."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from tests.test_apply_full_harness import ReleaseKey

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/release-vouch-previous.py"
APPLY = (REPO / "scripts/noo-apply.sh").read_bytes()
FETCH = (REPO / "scripts/noo-fetch.sh").read_bytes()


def run(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["python3", "-I", str(SCRIPT), *args], input=stdin, capture_output=True, text=True)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.mark.parametrize("this,tags,want", [
    ("0.6.27-rc.1", "0.6.25\n0.6.26\n0.6.27\n0.6.26-rc.1\n", "0.6.26"),
    ("0.6.27", "0.6.25\n0.6.26\n0.6.27\n", "0.6.26"),
    ("0.6.10", "0.6.9\n0.6.2\n0.6.10\n", "0.6.9"),
    ("0.6.1", "0.6.1\n0.6.2\n", ""),
])
def test_the_previous_final_is_the_highest_final_below(this: str, tags: str, want: str) -> None:
    r = run("prev-final", "--this", this, stdin=tags)
    assert r.returncode == 0 and r.stdout.strip() == want, (r.stdout, r.stderr)


class Prev:
    def __init__(self, tmp: Path, version: str = "0.6.26") -> None:
        self.key = ReleaseKey(tmp / "key")
        self.keys = tmp / "release_sig.rs"
        self.keys.write_text(f'pub const RELEASE_PUBKEYS_HEX: &[&str] = &["{self.key.pub_hex}"];\n')
        self.d = tmp / "prev"
        self.d.mkdir()
        self.version = version
        (self.d / "noo-apply.sh").write_bytes(APPLY)
        (self.d / "noo-fetch.sh").write_bytes(FETCH)
        self.cli = b"\x7fELF cli " + APPLY + b" between " + FETCH + b" end"
        (self.d / "noo-x86_64-unknown-linux-musl").write_bytes(self.cli)
        self.rows = {
            "noo-x86_64-unknown-linux-musl": sha(self.cli),
            "noo-hostd-x86_64-unknown-linux-gnu": "1" * 64,
            "noo-gateway-aarch64-unknown-linux-musl": "2" * 64,
            "noo-aarch64-apple-darwin": "3" * 64,
            "noo-node-agent-aarch64-apple-darwin": "4" * 64,
            "noo-hostd-aarch64-apple-darwin": "5" * 64,
            "noo-release-version": sha(f"{version}\n".encode()),
        }
        self.sign()

    def sign(self, key: ReleaseKey | None = None) -> None:
        text = "".join(f"{s}  {n}\n" for n, s in self.rows.items()).encode()
        (self.d / "sha256sums.txt").write_bytes(text)
        (self.d / "sha256sums.txt.sig").write_bytes((key or self.key).sign(text))

    def sums(self) -> subprocess.CompletedProcess:
        return run("sums", "--prev", self.version, "--dir", str(self.d), "--keys-from", str(self.keys))


def test_the_previous_finals_rows_are_derived_by_digest(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    r = p.sums()
    assert r.returncode == 0, r.stderr
    rows = set(r.stdout.split("\n"))
    assert f"{sha(APPLY)}  noo-apply.sh@v0.6.26" in rows and f"{sha(FETCH)}  noo-fetch.sh@v0.6.26" in rows
    for n in ("noo-hostd-x86_64-unknown-linux-gnu", "noo-gateway-aarch64-unknown-linux-musl", "noo-aarch64-apple-darwin",
              "noo-node-agent-aarch64-apple-darwin", "noo-hostd-aarch64-apple-darwin"):
        assert f"{p.rows[n]}  {n}@v0.6.26" in rows, n
    assert not any("unknown-linux-musl@v" in x and x.startswith(sha(p.cli)) for x in rows), "the Linux CLI is user code: not vouched"
    assert not any("noo-release-version" in x for x in rows)


def test_a_previous_list_not_signed_by_a_release_key_fails(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    p.sign(ReleaseKey(tmp_path / "other"))
    r = p.sums()
    assert r.returncode == 1 and "does not verify" in r.stderr


def test_a_cli_that_does_not_embed_the_tags_scripts_fails(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    (p.d / "noo-apply.sh").write_bytes(APPLY + b"\n# edited\n")
    r = p.sums()
    assert r.returncode == 1 and "does not embed scripts/noo-apply.sh" in r.stderr


def test_a_cli_that_is_not_the_signed_one_fails(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    (p.d / "noo-x86_64-unknown-linux-musl").write_bytes(p.cli + b"x")
    r = p.sums()
    assert r.returncode == 1 and "is not the one release 0.6.26 signed" in r.stderr


def test_a_list_of_another_release_fails(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    p.rows["noo-release-version"] = sha(b"0.6.25\n")
    p.sign()
    r = p.sums()
    assert r.returncode == 1 and "is not release 0.6.26's" in r.stderr


def test_the_previous_lock_is_verified_and_names_its_tag(tmp_path: Path) -> None:
    p = Prev(tmp_path)
    digest = "sha256:" + "c" * 64

    def lock(tag: str, key: ReleaseKey | None = None) -> subprocess.CompletedProcess:
        text = f"# stack {tag}\n# mesh-migration-head 0099_x\nnode-agent@{digest}\ngateway@sha256:{'d' * 64}\n".encode()
        (p.d / "stack-v0.6.26.lock").write_bytes(text)
        (p.d / "stack-v0.6.26.lock.sig").write_bytes((key or p.key).sign(text))
        return run("lock", "--prev", "0.6.26", "--dir", str(p.d), "--keys-from", str(p.keys))

    r = lock("v0.6.26")
    assert r.returncode == 0 and r.stdout.strip() == digest, (r.stdout, r.stderr)
    r = lock("v0.6.25")
    assert r.returncode == 1 and "is signed for" in r.stderr
    r = lock("v0.6.26", ReleaseKey(tmp_path / "other"))
    assert r.returncode == 1 and "does not verify" in r.stderr


def test_both_release_jobs_vouch_for_the_previous_final() -> None:
    cli = (REPO / ".github/workflows/noo-cli-release.yml").read_text()
    step = cli[cli.index("- name: Vouch for the previous final (i908)"):cli.index("- name: Sign the checksum manifest")]
    assert "release-vouch-previous.py sums" in step and ">> dist/sha256sums.txt" in step and "NOO_RELEASE_SIGNING_SEED" not in step
    img = (REPO / ".github/workflows/images-release.yml").read_text()
    step = img[img.index("- name: Record the node agent binary's sha256 per arch"):img.index("- name: Assemble + sign stack-$TAG.lock")]
    assert "release-vouch-previous.py lock" in step and "# node-agent-sha256@v$prev linux/$arch" in step
    assert "NOO_RELEASE_SIGNING_SEED" not in step
