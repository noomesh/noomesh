# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The REAL scripts/noo-apply.sh against crafted bundles (an earlier change review).

The block-level tests (test_apply_signature_lanes_retired.py,
test_apply_env_unit_shape.py) lift one function out of the applier. The
review's bypasses lived BETWEEN those functions — extraction before the
signature check, install blocks keyed on file presence, a rollover decided by
what was on disk — so this harness runs the whole script, top to bottom, in
its VERIFY-ONLY mode: every check runs, nothing is installed, and the anchor
paths (PKI, the node env, the installed applier) point into a temp dir. Only
that mode honours those overrides or skips the root check, and it exits
before the first write.

Each attack below was accepted by the applier this PR first shipped; each is
refused now, with the exit code and the reason pinned.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import subprocess
import tarfile
import time
from pathlib import Path

import re

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
AGENT_UNIT = (REPO / "node-agent-go/deploy/noo-node-agent.service").read_bytes()


def sh(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True)


# The root-run kinds the applier holds to the RELEASE-signed lists (§1c,
# i908), and the release asset each is listed under in sha256sums.txt.
RELEASE_ASSET = {
    "applier": "noo-apply.sh",
    "fetcher": "noo-fetch.sh",
    "hostd-binary": "noo-hostd-x86_64-unknown-linux-gnu",
    "harness-binary": "noo-gateway-x86_64-unknown-linux-musl",
}
RELEASE_KINDS = ("release-sums", "release-sums.sig", "release-version", "release-lock", "release-lock.sig")
ROOT_KINDS = (*RELEASE_ASSET, "agent-binary")


class ReleaseKey:
    """A throwaway Ed25519 release key: what the pipeline's seed is in production."""

    def __init__(self, d: Path) -> None:
        self.dir = d
        d.mkdir(exist_ok=True)
        self.key = d / "release.key"
        sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.key))
        der = subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"],
                             check=True, capture_output=True).stdout
        self.pub_hex = der[-32:].hex()

    def sign(self, data: bytes) -> bytes:
        """`noo-sig1.<base64url, unpadded>` over the exact bytes, as release_sig::sign writes it."""
        src, out = self.dir / "to-sign", self.dir / "sig.bin"
        src.write_bytes(data)
        sh("openssl", "pkeyutl", "-sign", "-inkey", str(self.key), "-rawin", "-in", str(src), "-out", str(out))
        return b"noo-sig1." + base64.urlsafe_b64encode(out.read_bytes()).rstrip(b"=") + b"\n"


class Fleet:
    """A controller's keys and one node's anchors, in a temp dir."""

    def __init__(self, tmp: Path, adopted: bool = True) -> None:
        self.tmp = tmp
        self.keys = tmp / "controller"
        self.pki = tmp / "node-pki"
        self.keys.mkdir()
        self.pki.mkdir()
        self.ca_key = self.keys / "ca.key"
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-nodes", "-keyout", str(self.ca_key), "-out", str(self.pki / "ca.crt"),
           "-days", "30", "-subj", "/CN=noo-test-ca")
        self.signing_key = self.keys / "signing.key"
        self.signing_pub = self.keys / "signing.pub"
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.signing_key))
        sh("openssl", "ec", "-in", str(self.signing_key), "-pubout", "-out", str(self.signing_pub))
        if adopted:
            (self.pki / "signing.pub").write_bytes(self.signing_pub.read_bytes())
        self.node_env = tmp / "node.env"
        self.node_env.write_text("NODE_ID=host3\n")
        # The INSTALLED applier is this one (the downgrade floor reads it).
        self.self_path = tmp / "noo-apply"
        self.self_path.write_bytes(APPLIER.read_bytes())
        self.release = ReleaseKey(tmp / "release")
        self.floor = tmp / "release-floor"
        stub = tmp / "stub"
        stub.mkdir()
        (stub / "logger").write_text("#!/bin/sh\nexit 0\n")
        (stub / "logger").chmod(0o755)
        self.path = f"{stub}:/usr/bin:/bin"

    def release_proof(self, files: dict[str, bytes], *, version: str = "0.6.27", stack: str = "v0.6.27",
                      sums_key: "ReleaseKey | None" = None, lock_key: "ReleaseKey | None" = None,
                      unlisted_kinds: tuple[str, ...] = (), extra_sums_rows: tuple[str, ...] = (),
                      extra_lock_rows: tuple[str, ...] = ()) -> dict[str, bytes]:
        """The release-signed lists that vouch for every root kind in `files`
        (except `unlisted_kinds`): what provision attaches from the release."""
        ver = f"{version}\n".encode()
        rows = [f"{hashlib.sha256(b'unrelated').hexdigest()}  noo-x86_64-unknown-linux-musl"]
        for kind, asset in RELEASE_ASSET.items():
            if kind in files and kind not in unlisted_kinds:
                rows.append(f"{hashlib.sha256(files[kind]).hexdigest()}  {asset}")
        rows.append(f"{hashlib.sha256(ver).hexdigest()}  noo-release-version")
        rows += list(extra_sums_rows)
        sums = ("\n".join(rows) + "\n").encode()
        proof = {"release-sums": sums, "release-sums.sig": (sums_key or self.release).sign(sums), "release-version": ver}
        if "agent-binary" in files:
            agent = "" if "agent-binary" in unlisted_kinds else \
                f"# node-agent-sha256 linux/amd64 {hashlib.sha256(files['agent-binary']).hexdigest()}\n"
            lock = (f"# stack {stack}\n# mesh-migration-head 0001\n"
                    f"node-agent@sha256:{'a' * 64}\n{agent}" + "".join(r + "\n" for r in extra_lock_rows)).encode()
            proof["release-lock"] = lock
            proof["release-lock.sig"] = (lock_key or self.release).sign(lock)
        return proof

    def bundle(self, files: dict[str, bytes], key: Path | None = None, *,
               extra: list[tarfile.TarInfo] | None = None,
               unlisted: dict[str, bytes] | None = None, issued: str | None = None,
               extra_lines: list[str] | None = None, release: bool = True) -> Path:
        """Manifest + signature over `files`; `unlisted` ride without a line.
        A bundle carrying root code also carries the release lists for it
        (unless `release=False` or `files` brings its own)."""
        if release and any(k in files for k in ROOT_KINDS) and not any(k in files for k in RELEASE_KINDS):
            files = {**files, **self.release_proof(files)}
        lines = ["#noo-bundle 2", "#node host3", f"#issued {issued if issued is not None else int(time.time())}"]
        for kind, body in files.items():
            lines.append(f"{hashlib.sha256(body).hexdigest()}  {kind}")
        lines += extra_lines or []
        manifest = ("\n".join(lines) + "\n").encode()
        mpath = self.tmp / "manifest"
        mpath.write_bytes(manifest)
        sig = self.tmp / "manifest.sig"
        sh("openssl", "dgst", "-sha256", "-sign", str(key or self.signing_key), "-out", str(sig), str(mpath))
        out = self.tmp / "bundle.tar"
        with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as t:
            def add(name: str, body: bytes) -> None:
                ti = tarfile.TarInfo(name)
                ti.size = len(body)
                ti.mode = 0o644
                t.addfile(ti, io.BytesIO(body))
            add("manifest", manifest)
            add("manifest.sig", sig.read_bytes())
            d = tarfile.TarInfo("files")
            d.type = tarfile.DIRTYPE
            d.mode = 0o755
            t.addfile(d)
            for kind, body in {**files, **(unlisted or {})}.items():
                add(f"files/{kind}", body)
            for ti in extra or []:
                t.addfile(ti)
        return out

    def apply(self, bundle: Path, applier: Path = APPLIER) -> subprocess.CompletedProcess:
        env = {
            "PATH": self.path,
            "NOO_APPLY_VERIFY_ONLY": "1",
            "NOO_APPLY_PKI": str(self.pki),
            "NOO_APPLY_NODE_ENV": str(self.node_env),
            "NOO_APPLY_SELF": str(self.self_path),
            "NOO_APPLY_RELEASE_PUBKEYS_HEX": self.release.pub_hex,
            "NOO_APPLY_RELEASE_FLOOR": str(self.floor),
        }
        return subprocess.run(["bash", str(applier), str(bundle)], capture_output=True, text=True, env=env)


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path)


def refused(r: subprocess.CompletedProcess, code: int, why: str) -> None:
    assert r.returncode == code, (r.returncode, r.stdout, r.stderr)
    assert why in r.stderr, r.stderr
    assert "nothing installed" not in r.stdout


# ── floors: a well-formed bundle passes every check ─────────────────────────

def test_floor_a_signed_bundle_passes(fleet: Fleet) -> None:
    r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n", "agent-unit": AGENT_UNIT}))
    assert r.returncode == 0, r.stderr
    assert "verified-by: signing-key" in r.stdout and "nothing installed" in r.stdout


def test_floor_first_adoption_carrying_only_the_key(tmp_path: Path) -> None:
    f = Fleet(tmp_path, adopted=False)
    r = f.apply(f.bundle({"signing-pub": f.signing_pub.read_bytes()}, key=f.ca_key))
    assert r.returncode == 0, r.stderr
    assert "verified-by: ca-rollover" in r.stdout


def test_floor_the_same_generation_applier_rides(fleet: Fleet) -> None:
    newer = APPLIER.read_bytes().replace(b"# Copyright 2026 PersonifAI LLC", b"# Copyright 2026 PersonifAI LLC (rebuilt)", 1)
    r = fleet.apply(fleet.bundle({"applier": newer}))
    assert r.returncode == 0, r.stderr


# ── item 1: tar members that are not regular files ──────────────────────────

def test_a_symlink_member_is_refused_before_extraction(fleet: Fleet) -> None:
    ln = tarfile.TarInfo("files/ca.pub")
    ln.type = tarfile.SYMTYPE
    ln.linkname = str(fleet.pki / "signing.pub")
    r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n"}, extra=[ln]))
    refused(r, 65, "not a regular file")
    # The anchor the symlink aimed at is untouched.
    assert (fleet.pki / "signing.pub").read_bytes() == fleet.signing_pub.read_bytes()


def test_a_top_level_symlink_named_like_the_ca_key_is_refused(fleet: Fleet) -> None:
    ln = tarfile.TarInfo("ca.pub")
    ln.type = tarfile.SYMTYPE
    ln.linkname = str(fleet.pki / "signing.pub")
    refused(fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n"}, extra=[ln])), 65, "ca.pub")


def test_a_hardlink_member_is_refused(fleet: Fleet) -> None:
    hl = tarfile.TarInfo("files/node.key")
    hl.type = tarfile.LNKTYPE
    hl.linkname = "manifest"
    refused(fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n"}, extra=[hl])), 65, "not a regular file")


def test_a_path_outside_the_layout_is_refused(fleet: Fleet) -> None:
    ti = tarfile.TarInfo("etc/cron.d/x")
    ti.size = 1
    b = fleet.bundle({"agent-env": b"NODE_ID=host3\n"})
    with tarfile.open(b, "a") as t:
        t.addfile(ti, io.BytesIO(b"x"))
    refused(fleet.apply(b), 65, "etc/cron.d/x")


# ── item 2: a file the signed manifest does not name ────────────────────────

def test_an_unmanifested_file_is_refused(fleet: Fleet) -> None:
    r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n"},
                                 unlisted={"agent-unit": b"[Service]\nExecStart=/bin/sh -c id\n"}))
    refused(r, 65, "does not name")


def test_an_unmanifested_signing_pub_does_not_make_a_rollover(tmp_path: Path) -> None:
    f = Fleet(tmp_path, adopted=False)
    # CA-signed, manifest names only agent-binary; signing-pub rides unlisted.
    r = f.apply(f.bundle({"agent-binary": b"\x7fELFpwn"}, key=f.ca_key,
                         unlisted={"signing-pub": f.signing_pub.read_bytes()}))
    refused(r, 77, "CA-signed apply lane is retired")


# ── items 3/4: CR and NUL ────────────────────────────────────────────────────

@pytest.mark.parametrize("kind,body", [
    ("agent-env", b"NODE_ID=host3\nLOG_LEVEL=info\rLD_PRELOAD=/tmp/x.so\n"),
    ("agent-env", b"NODE_ID=host3\nLOG_LEVEL=info\x00LD_PRELOAD=/tmp/x.so\n"),
    ("agent-unit", AGENT_UNIT.replace(b"[Service]\n", b"[Service]\nDescription=x\rExecStartPre=/bin/sh -c id\n", 1)),
    ("fleet-secrets", b"NODE=host3\nNOO_CLUSTER_SECRET=x\rLD_PRELOAD=/tmp/x.so\n"),
    ("nats-creds", b"NODE=host3\nNATS_NODE_USER=host3\nNATS_NODE_PASSWORD=x\rPATH=/tmp\n"),
], ids=["agent-env-cr", "agent-env-nul", "agent-unit-cr", "fleet-secrets-cr", "nats-creds-cr"])
def test_a_carriage_return_or_nul_is_refused(fleet: Fleet, kind: str, body: bytes) -> None:
    refused(fleet.apply(fleet.bundle({kind: body})), 65, "carriage return or NUL")


# ── items 5/6: units are the shipped bytes, nothing else ────────────────────

@pytest.mark.parametrize("old,new", [
    (b"User=noo-agent\n", b""),  # then put it where systemd ignores it:
    (b"StandardOutput=journal", b"StandardOutput=file:/etc/shadow"),
    (b"WantedBy=multi-user.target", b"WantedBy=multi-user.target emergency.target"),
    (b"Type=simple", b"Type=forking"),
], ids=["user-in-unit-section", "stdout-file", "wantedby", "type"])
def test_a_unit_that_is_not_the_shipped_bytes_is_refused(fleet: Fleet, old: bytes, new: bytes) -> None:
    assert old in AGENT_UNIT
    unit = AGENT_UNIT.replace(old, new, 1)
    if old == b"User=noo-agent\n":
        unit = unit.replace(b"[Unit]\n", b"[Unit]\nUser=noo-agent\n", 1)
    refused(fleet.apply(fleet.bundle({"agent-unit": unit})), 65, "is not the unit this release ships")


# ── item 7: the CA delivers a key, never code ───────────────────────────────

@pytest.mark.parametrize("adopted", [False, True])
def test_a_ca_signed_rollover_carrying_code_is_refused(tmp_path: Path, adopted: bool) -> None:
    f = Fleet(tmp_path, adopted=adopted)
    files = {"signing-pub": f.signing_pub.read_bytes(), "agent-binary": b"\x7fELFpwn"}
    refused(f.apply(f.bundle(files, key=f.ca_key)), 77, "may carry signing-pub and NOTHING else")


def test_a_ca_signed_rollover_carrying_an_applier_is_refused(tmp_path: Path) -> None:
    f = Fleet(tmp_path, adopted=False)
    files = {"signing-pub": f.signing_pub.read_bytes(), "applier": APPLIER.read_bytes()}
    refused(f.apply(f.bundle(files, key=f.ca_key)), 77, "NOTHING else")


# ── item 8: no applier downgrade ────────────────────────────────────────────

def test_an_older_applier_is_refused(fleet: Fleet) -> None:
    # §1b's floor, past §1c: the installed applier is a later generation (3)
    # than the release-listed one in the bundle (2).
    gen3 = fleet.tmp / "noo-apply-gen3"
    gen3.write_bytes(re.sub(rb"(?m)^NOO_APPLY_GENERATION=\d+$", b"NOO_APPLY_GENERATION=3", APPLIER.read_bytes()))
    fleet.self_path.write_bytes(gen3.read_bytes())
    refused(fleet.apply(fleet.bundle({"applier": APPLIER.read_bytes()}), applier=gen3), 65, "older than this one")


def test_an_applier_with_no_generation_never_installs(fleet: Fleet) -> None:
    old = b"\n".join(l for l in APPLIER.read_bytes().split(b"\n") if not l.startswith(b"NOO_APPLY_GENERATION="))
    refused(fleet.apply(fleet.bundle({"applier": old})), 75, "applier generation 0, which has no release check")


def test_the_overrides_are_honoured_only_in_verify_only_mode() -> None:
    text = APPLIER.read_text()
    seam = text[text.index('VERIFY_ONLY="${NOO_APPLY_VERIFY_ONLY:-0}"'):text.index('CA="$PKI/ca.crt"')]
    real = seam[seam.index("else"):]
    assert "NOO_APPLY_PKI" not in real and "PKI=/etc/noo/pki" in real
    assert '[ "$(id -u)" = 0 ]' in real
    # …and verify-only exits before the first install.
    assert text.index('verify-only: every check passed; nothing installed') < text.index("install -d -m 750 -o root -g noo-agent")
    assert os.access(APPLIER, os.R_OK)


# ── second review, H1: the signed header is never shell arithmetic ─────────

@pytest.mark.parametrize("issued", ["NOW[$(touch {m})]", "1+1", "0x10", "-1", "1 ", "99999999999999"],
                         ids=["cmd-subst-in-subscript", "expression", "hex", "negative", "trailing-space", "13-digits"])
def test_a_non_numeric_issued_stamp_runs_nothing_and_is_refused(fleet: Fleet, issued: str) -> None:
    marker = fleet.tmp / "PWNED"
    b = fleet.bundle({"agent-env": b"NODE_ID=host3\n"}, issued=issued.format(m=marker))
    r = fleet.apply(b)
    assert not marker.exists(), "the #issued header ran a command"
    assert r.returncode != 0, (r.stdout, r.stderr)
    assert "REFUSED" in r.stderr, r.stderr


def test_a_ca_signed_rollover_with_an_arithmetic_header_runs_nothing(tmp_path: Path) -> None:
    f = Fleet(tmp_path, adopted=False)
    marker = tmp_path / "PWNED"
    b = f.bundle({"signing-pub": f.signing_pub.read_bytes()}, key=f.ca_key, issued=f"NOW[$(touch {marker})]")
    r = f.apply(b)
    assert not marker.exists() and r.returncode != 0, (r.stdout, r.stderr)


# ── second review, L4: one manifest shape for every reader ──────────────────

@pytest.mark.parametrize("line", [
    " " + "a" * 64 + "  agent-unit",           # leading space: `read` trims it, awk does not care
    "a" * 64 + "\tagent-unit",                 # a tab: split one way by read, another by grep
    "a" * 64 + "  agent-unit extra",            # a third field
    "#nodes host3",                             # a header-looking line
], ids=["leading-space", "tab", "third-field", "odd-header"])
def test_a_manifest_line_any_reader_could_split_differently_is_refused(fleet: Fleet, line: str) -> None:
    r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n"}, extra_lines=[line]))
    assert r.returncode == 65, (r.stdout, r.stderr)
    assert "manifest has a line" in r.stderr


def test_the_retired_lane_variable_may_only_say_zero(fleet: Fleet) -> None:
    for v, ok in [(b"0", True), (b"", False), (b"1", False)]:
        r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\nNOO_APPLY_ACCEPT_CA_SIGNED=" + v + b"\n"}))
        assert (r.returncode == 0) == ok, (v, r.stdout, r.stderr)

