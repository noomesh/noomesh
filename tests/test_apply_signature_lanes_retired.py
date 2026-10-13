# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change + A2, behaviourally, in the Linux applier.

`bundle_signature_lane` in scripts/noo-apply.sh is lifted out between its
markers and run against real openssl keys and real signatures (the way
test_host_telemetry_applier.py drives its block). What it pins:

  A1  the CA-signed compatibility lane is RETIRED: a CA signature over a
      bundle that is not a signing-key rollover is refused (77), on a node
      that has adopted and one that has not, and NOO_APPLY_ACCEPT_CA_SIGNED=1
      cannot reopen it. Before the retirement this bundle applied as
      `ca-legacy` by default.
  A2  a CA-signed rollover replaces an ADOPTED signing key only when the key
      the node holds countersigned it (`manifest.xsig*`); first adoption
      (no signing.pub yet) still needs only the CA.

The Rust twin (the macOS applier) is `node_fetch.rs`'s R26 tests.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"


def block() -> str:
    m = re.search(r"# BEGIN signature_lane\n(.*?)# END signature_lane", APPLIER.read_text(), re.S)
    assert m, "bundle_signature_lane is not delimited in noo-apply.sh"
    body = m.group(1)
    assert "bundle_signature_lane()" in body
    return body


def sh(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(args, check=True, cwd=cwd, capture_output=True)


def keypair(d: Path, name: str) -> tuple[Path, Path]:
    key, pub = d / f"{name}.key", d / f"{name}.pub"
    sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    sh("openssl", "ec", "-in", str(key), "-pubout", "-out", str(pub))
    return key, pub


class Node:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.pki = tmp / "pki"
        self.work = tmp / "work"
        self.keys = tmp / "keys"
        for d in (self.pki, self.work / "files", self.keys):
            d.mkdir(parents=True)
        self.ca_key = self.keys / "ca.key"
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-nodes", "-keyout", str(self.ca_key), "-out", str(self.pki / "ca.crt"),
           "-days", "30", "-subj", "/CN=noo-test-ca")
        self.signing_key, self.signing_pub = keypair(self.keys, "signing")

    def adopt(self, pub: Path) -> None:
        (self.pki / "signing.pub").write_bytes(pub.read_bytes())

    def stage(self, kind: str, body: str) -> None:
        (self.work / "files" / kind).write_text(body)

    def sign(self, key: Path, out: str = "manifest.sig") -> None:
        manifest = self.work / "manifest"
        if not manifest.exists():
            lines = ["#noo-bundle 2", "#node host3", "#issued 1"]
            for f in sorted((self.work / "files").iterdir()):
                lines.append(f"{'0' * 64}  {f.name}")
            manifest.write_text("\n".join(lines) + "\n")
        sh("openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(self.work / out), str(manifest))

    def lane(self, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        script = f"""set -eu
logger() {{ :; }}
{block()}
_keys="$(mktemp -d)"
bundle_signature_lane "{self.pki}" "{self.work}" "$_keys"
echo "SIG_VIA=$SIG_VIA"
"""
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", **(env or {})})


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def test_floor_a_signing_key_bundle_verifies(node: Node) -> None:
    node.adopt(node.signing_pub)
    node.stage("agent-binary", "x")
    node.sign(node.signing_key)
    r = node.lane()
    assert r.returncode == 0, r.stderr
    assert "SIG_VIA=signing-key" in r.stdout


@pytest.mark.parametrize("adopted", [True, False])
def test_the_ca_signed_lane_is_retired(node: Node, adopted: bool) -> None:
    if adopted:
        node.adopt(node.signing_pub)
    node.stage("agent-binary", "#!/bin/sh\necho pwned\n")
    node.sign(node.ca_key)
    r = node.lane()
    assert r.returncode == 77, (r.returncode, r.stdout, r.stderr)
    assert "CA-signed apply lane is retired" in r.stderr
    assert "SIG_VIA=" not in r.stdout


def test_the_retired_switch_cannot_reopen_the_lane(node: Node) -> None:
    node.adopt(node.signing_pub)
    node.stage("agent-binary", "x")
    node.sign(node.ca_key)
    r = node.lane({"NOO_APPLY_ACCEPT_CA_SIGNED": "1"})
    assert r.returncode == 77, (r.stdout, r.stderr)
    assert "retired" in r.stderr and "ignored" in r.stderr


def test_first_adoption_is_a_ca_signed_rollover(node: Node) -> None:
    node.stage("signing-pub", node.signing_pub.read_text())
    node.sign(node.ca_key)
    r = node.lane()
    assert r.returncode == 0, r.stderr
    assert "SIG_VIA=ca-rollover" in r.stdout


def test_first_adoption_may_not_carry_code(node: Node) -> None:
    node.stage("signing-pub", node.signing_pub.read_text())
    node.stage("agent-binary", "x")
    node.sign(node.ca_key)
    r = node.lane()
    assert r.returncode == 77, (r.stdout, r.stderr)
    assert "NOTHING else" in r.stderr


def test_a_ca_only_rollover_cannot_replace_an_adopted_key(node: Node) -> None:
    held_key, held_pub = keypair(node.keys, "held")
    node.adopt(held_pub)
    node.stage("signing-pub", node.signing_pub.read_text())
    node.sign(node.ca_key)
    r = node.lane()
    assert r.returncode == 77, (r.stdout, r.stderr)
    assert "did not countersign" in r.stderr
    # A countersignature by a key the node does not hold is no better.
    stranger_key, _ = keypair(node.keys, "stranger")
    node.sign(stranger_key, "manifest.xsig.0")
    assert node.lane().returncode == 77


def test_a_rollover_countersigned_by_the_held_key_is_accepted(node: Node) -> None:
    held_key, held_pub = keypair(node.keys, "held")
    node.adopt(held_pub)
    node.stage("signing-pub", node.signing_pub.read_text())
    node.sign(node.ca_key)
    node.sign(node.signing_key, "manifest.xsig.0")
    node.sign(held_key, "manifest.xsig.1")
    r = node.lane()
    assert r.returncode == 0, r.stderr
    assert "SIG_VIA=ca-rollover-countersigned" in r.stdout


def test_a_strangers_key_authorises_nothing(node: Node) -> None:
    stranger_key, stranger_pub = keypair(node.keys, "stranger")
    node.stage("signing-pub", stranger_pub.read_text())
    node.sign(stranger_key)
    r = node.lane()
    assert r.returncode == 77, (r.stdout, r.stderr)


def test_the_applier_reports_the_lane_retired() -> None:
    text = APPLIER.read_text()
    assert 'echo "ca-lane: retired"' in text
    assert "NOO_APPLY_ACCEPT_CA_SIGNED:-1" not in text, "the compatibility default is back"
