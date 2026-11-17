# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noo-apply §1c (i908): a node installs root code only if the RELEASE key listed it.

The fleet signing key decides what a node applies; since generation 2 of the
applier it no longer decides what root code the node runs. Every root-run
payload (applier, fetcher, hostd, harness, agent) must be listed by sha256 in
a list the release key signed — sha256sums.txt for the first four, the stack
lock's `# node-agent-sha256` rows for the agent — and that list must not be
older than the one this node last applied.

Every check below runs the REAL applier in its verify-only mode
(tests/test_apply_full_harness.py's Fleet), with REAL Ed25519 signatures made
by a throwaway key. The applier reads that key's hex from
NOO_APPLY_RELEASE_PUBKEYS_HEX, which it honours ONLY in verify-only mode — a
mode that installs nothing and exits before the first write
(test_the_test_key_seam_is_verify_only_mode below pins that).
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

from tests.test_apply_full_harness import APPLIER, AGENT_UNIT, RELEASE_ASSET, Fleet, ReleaseKey

REPO = Path(__file__).resolve().parents[1]
TEXT = APPLIER.read_text()
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 64

PAYLOADS = {
    "applier": APPLIER.read_bytes().replace(b"# Copyright 2026 PersonifAI LLC", b"# Copyright 2026 PersonifAI LLC (next)", 1),
    "fetcher": (REPO / "scripts/noo-fetch.sh").read_bytes(),
    "hostd-binary": ELF + b"hostd",
    "harness-binary": ELF + b"gateway",
    "agent-binary": ELF + b"agent",
}


@pytest.fixture
def fleet(tmp_path: Path) -> Fleet:
    return Fleet(tmp_path)


def refused(r: subprocess.CompletedProcess, why: str) -> str:
    assert r.returncode == 75, (r.returncode, r.stdout, r.stderr)
    assert why in r.stderr, r.stderr
    assert "nothing installed" not in r.stdout
    line = [l for l in r.stderr.splitlines() if "REFUSED" in l][-1]
    assert "roll to a published release or rc" in line, line
    return line


def passed(r: subprocess.CompletedProcess) -> None:
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "nothing installed" in r.stdout


# ── the floor: listed root code passes, config needs no list ───────────────

def test_every_listed_root_kind_passes(fleet: Fleet) -> None:
    r = fleet.apply(fleet.bundle(dict(PAYLOADS)))
    passed(r)
    assert "release-check: verified release=0.6.27 stack=v0.6.27" in r.stdout


def test_a_config_only_bundle_needs_no_release_list(fleet: Fleet) -> None:
    r = fleet.apply(fleet.bundle({"agent-env": b"NODE_ID=host3\n", "agent-unit": AGENT_UNIT}))
    passed(r)
    assert "release-check: verified release=none stack=none" in r.stdout


# ── a root payload not in the list ──────────────────────────────────────────

@pytest.mark.parametrize("kind", list(PAYLOADS))
def test_a_root_payload_not_in_the_release_list_is_refused(fleet: Fleet, kind: str) -> None:
    files = {kind: PAYLOADS[kind]}
    files.update(fleet.release_proof(files, unlisted_kinds=(kind,)))
    line = refused(fleet.apply(fleet.bundle(files)), "is not in")
    assert kind in line and hashlib.sha256(PAYLOADS[kind]).hexdigest() in line, line


@pytest.mark.parametrize("kind", list(PAYLOADS))
def test_root_code_without_any_release_list_is_refused(fleet: Fleet, kind: str) -> None:
    line = refused(fleet.apply(fleet.bundle({kind: PAYLOADS[kind]}, release=False)), "no release-signed list")
    assert kind in line


def test_a_payload_listed_under_another_kinds_name_is_refused(fleet: Fleet) -> None:
    # A real release binary, delivered as a different root kind: the hostd
    # bytes listed as the gateway asset may not install as hostd.
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    proof = fleet.release_proof({"harness-binary": PAYLOADS["hostd-binary"]})
    refused(fleet.apply(fleet.bundle({**files, **proof})), "hostd-binary")


def test_an_agent_listed_in_the_lock_but_not_this_one_is_refused(fleet: Fleet) -> None:
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    proof = fleet.release_proof({"agent-binary": ELF + b"another agent"})
    refused(fleet.apply(fleet.bundle({**files, **proof})), "not in stack v0.6.27's signed lock")


def test_an_agent_without_the_stack_lock_is_refused(fleet: Fleet) -> None:
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    proof = {k: v for k, v in fleet.release_proof(files).items() if not k.startswith("release-lock")}
    refused(fleet.apply(fleet.bundle({**files, **proof})), "stack lock")


# ── the signature ───────────────────────────────────────────────────────────

def test_a_list_signed_by_another_key_is_refused(fleet: Fleet, tmp_path: Path) -> None:
    other = ReleaseKey(tmp_path / "not-the-release")
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    refused(fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, sums_key=other)})),
            "release-sums — its signature does not verify")


def test_a_lock_signed_by_another_key_is_refused(fleet: Fleet, tmp_path: Path) -> None:
    other = ReleaseKey(tmp_path / "not-the-release")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    refused(fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, lock_key=other)})),
            "release-lock — its signature does not verify")


def test_a_list_edited_after_signing_is_refused(fleet: Fleet) -> None:
    files = {"hostd-binary": ELF + b"evil"}
    proof = fleet.release_proof({"hostd-binary": PAYLOADS["hostd-binary"]})
    # The genuine signature, over a list with one more row.
    proof["release-sums"] += f"{hashlib.sha256(files['hostd-binary']).hexdigest()}  noo-hostd-x86_64-unknown-linux-gnu\n".encode()
    refused(fleet.apply(fleet.bundle({**files, **proof})), "does not verify")


@pytest.mark.parametrize("sig", [b"", b"noo-sig1.", b"noo-sig1." + b"A" * 85, b"noo-sig2." + b"A" * 86, b"noo-sig1.$(id)" + b"A" * 80])
def test_a_malformed_signature_is_refused(fleet: Fleet, sig: bytes) -> None:
    files = {"fetcher": PAYLOADS["fetcher"]}
    proof = fleet.release_proof(files)
    proof["release-sums.sig"] = sig + b"\n"
    refused(fleet.apply(fleet.bundle({**files, **proof})), "does not verify")


def test_an_openssl_that_cannot_verify_ed25519_refuses_and_says_so(fleet: Fleet) -> None:
    # An OpenSSL 1.1.1 has no `pkeyutl -rawin`: say so, never skip the check.
    stub = fleet.tmp / "stub" / "openssl"
    real = subprocess.run(["sh", "-c", "command -v openssl"], capture_output=True, text=True).stdout.strip()
    stub.write_text(f'#!/bin/sh\n[ "$1 $2" = "pkeyutl -help" ] && {{ echo "Usage: pkeyutl"; exit 1; }}\n'
                    f'[ "$1" = version ] && {{ echo "OpenSSL 1.1.1f  31 Mar 2020"; exit 0; }}\nexec {real} "$@"\n')
    stub.chmod(0o755)
    refused(fleet.apply(fleet.bundle({"applier": PAYLOADS["applier"]})), "OpenSSL 3 is needed")


# ── the version the list names, and the floor ───────────────────────────────

def test_a_version_text_the_list_does_not_name_is_refused(fleet: Fleet) -> None:
    files = {"fetcher": PAYLOADS["fetcher"]}
    proof = fleet.release_proof(files)
    proof["release-version"] = b"0.6.99\n"
    refused(fleet.apply(fleet.bundle({**files, **proof})), "is not the release the signed list names")


@pytest.mark.parametrize("floor,version,ok", [
    ("0.6.28", "0.6.27", False),
    ("0.6.27", "0.6.27-rc.3", False),   # the final is newer than its rcs
    ("0.6.27-rc.3", "0.6.27-rc.2", False),
    ("0.6.27", "0.6.27", True),
    ("0.6.27-rc.3", "0.6.27", True),
    ("0.6.9", "0.6.10", True),          # numeric, not string, order
    ("1.0.0", "0.99.99", False),
])
def test_the_release_floor(fleet: Fleet, floor: str, version: str, ok: bool) -> None:
    fleet.floor.write_text(f"# test\nrelease {floor}\n")
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, version=version)}))
    if ok:
        passed(r)
    else:
        refused(r, f"already applied release {floor}")


@pytest.mark.parametrize("floor,tag,ok", [("v0.6.28", "v0.6.27", False), ("v0.6.27", "v0.6.27", True), ("0.6.26", "stack-v0.6.27", True)])
def test_the_stack_floor(fleet: Fleet, floor: str, tag: str, ok: bool) -> None:
    fleet.floor.write_text(f"stack {floor}\n")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, stack=tag)}))
    if ok:
        passed(r)
    else:
        refused(r, f"already applied stack {floor}")


def test_a_floor_record_that_is_not_a_version_refuses(fleet: Fleet) -> None:
    fleet.floor.write_text("release $(id)\n")
    refused(fleet.apply(fleet.bundle({"fetcher": PAYLOADS["fetcher"]})), "is not a version")


def _floor_fns() -> str:
    block = TEXT[TEXT.index("# BEGIN release_check"):TEXT.index("# END release_check")]
    return block


def _write_floor(tmp: Path, *calls: tuple[str, str]) -> str:
    floor = tmp / "floor"
    script = _floor_fns() + "\n" + "\n".join(f'release_floor_write "{v}" "{s}"' for v, s in calls)
    subprocess.run(["bash", "-c", f"set -eu\nVERIFY_ONLY=0\nRELEASE_FLOOR={floor}\n{script}"], check=True, capture_output=True)
    return floor.read_text() if floor.exists() else ""


def test_the_floor_record_rises_and_never_falls(tmp_path: Path) -> None:
    out = _write_floor(tmp_path, ("0.6.27", "v0.6.27"), ("0.6.26", ""), ("", "v0.6.25"), ("0.6.28-rc.1", ""))
    assert "release 0.6.28-rc.1\n" in out and "stack v0.6.27\n" in out, out
    empty = tmp_path / "nothing-verified"
    empty.mkdir()
    assert _write_floor(empty, ("", "")) == "", "a config-only apply wrote a floor"


def test_the_floor_is_written_only_after_every_install() -> None:
    write = TEXT.index('release_floor_write "$RELEASE_OK_VERSION" "$RELEASE_OK_STACK"')
    for install in ('install -m 755 -o root -g root "$WORK/files/agent-binary"',
                    'install -m 755 -o root -g root "$WORK/files/hostd-binary"',
                    'install -m 755 -o root -g root "$WORK/files/harness-binary"',
                    'install -m 755 -o root -g root "$WORK/files/fetcher"'):
        assert TEXT.index(install) < write, install
    assert write < TEXT.index('echo "applied:$applied"')


# ── signing-pub and the applier: no lane skips the check ───────────────────

def test_a_signing_key_rollover_cannot_carry_unlisted_root_code(fleet: Fleet) -> None:
    # A re-key bundle (signed by the key the node holds) carrying an applier
    # the release never published: the re-key does not open a lane.
    files = {"signing-pub": fleet.signing_pub.read_bytes(), "applier": PAYLOADS["applier"]}
    files.update(fleet.release_proof(files, unlisted_kinds=("applier",)))
    refused(fleet.apply(fleet.bundle(files)), "applier")


def test_a_signing_key_rollover_alone_needs_no_list(fleet: Fleet) -> None:
    passed(fleet.apply(fleet.bundle({"signing-pub": fleet.signing_pub.read_bytes()})))


def test_the_check_runs_before_the_applier_replaces_itself() -> None:
    assert TEXT.index('release_check "$WORK" "$KEYS"') < TEXT.index("# ── 1b. Applier self-update comes FIRST")
    assert TEXT.index('release_check "$WORK" "$KEYS"') > TEXT.index("bundle_signature_lane \"$PKI\" \"$WORK\" \"$KEYS\"")


def test_the_check_does_not_read_any_key_a_bundle_installs() -> None:
    block = _floor_fns()
    for anchor in ("signing.pub", "ca.crt", "$PKI", "SIGNPUB"):
        code = "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))
        assert anchor not in code, anchor


def test_a_generation_1_applier_is_refused(fleet: Fleet) -> None:
    old = re.sub(rb"(?m)^NOO_APPLY_GENERATION=\d+$", b"NOO_APPLY_GENERATION=1", APPLIER.read_bytes())
    r = fleet.apply(fleet.bundle({"applier": old}))
    assert r.returncode == 65 and "generation 1, older than this one (2)" in r.stderr, (r.stdout, r.stderr)


# ── the pins ────────────────────────────────────────────────────────────────

def test_the_pinned_release_keys_are_the_clis() -> None:
    rs = (REPO / "noo-cli/src/release_sig.rs").read_text()
    m = re.search(r"pub const RELEASE_PUBKEYS_HEX: &\[&str\] = &\[(.*?)\];", rs, re.S)
    assert m
    cli = re.findall(r'"([0-9a-f]{64})"', m.group(1))
    sh = re.search(r'^RELEASE_PUBKEYS_HEX="([^"]*)"$', TEXT, re.M)
    assert sh and sh.group(1).split() == cli and cli


def test_the_test_key_seam_is_verify_only_mode() -> None:
    # The one place the override is read, inside the verify-only guard…
    assert TEXT.count("NOO_APPLY_RELEASE_PUBKEYS_HEX") == 2
    guard = 'if [ "$VERIFY_ONLY" = 1 ] && [ -n "${NOO_APPLY_RELEASE_PUBKEYS_HEX:-}" ]; then\n    RELEASE_PUBKEYS_HEX="$NOO_APPLY_RELEASE_PUBKEYS_HEX"\nfi'
    assert guard in TEXT
    # …the floor override likewise…
    seam = TEXT[TEXT.index('VERIFY_ONLY="${NOO_APPLY_VERIFY_ONLY:-0}"'):TEXT.index('CA="$PKI/ca.crt"')]
    assert "NOO_APPLY_RELEASE_FLOOR" not in seam[seam.index("else"):]
    assert TEXT.count("NOO_APPLY_RELEASE_FLOOR") == 1
    # …and verify-only mode installs nothing: it exits before the first write,
    # and the applier's own self-replace is skipped in it.
    assert TEXT.index("verify-only: every check passed; nothing installed") < TEXT.index("install -d -m 750 -o root -g noo-agent")
    assert 'if [ "$cur" != "$have" ] && [ "$VERIFY_ONLY" != 1 ]; then' in TEXT


def test_release_asset_names_are_the_published_ones() -> None:
    wf = (REPO / ".github/workflows/noo-cli-release.yml").read_text()
    for kind, asset in RELEASE_ASSET.items():
        assert re.search(TEXT_ASSET_RE[kind], asset), (kind, asset)
    assert "dist/noo-apply.sh" in wf and "dist/noo-fetch.sh" in wf
    sums = wf[wf.index("> sha256sums.txt") - 300:wf.index("> sha256sums.txt")]
    assert "noo-apply.sh" in sums and "noo-fetch.sh" in sums


TEXT_ASSET_RE = {
    k: subprocess.run(["bash", "-c", TEXT[TEXT.index("release_asset_re() {"):TEXT.index("\n}\n", TEXT.index("release_asset_re() {")) + 3]
                      + f"\nrelease_asset_re {k}"], capture_output=True, text=True, check=True).stdout.strip()
    for k in RELEASE_ASSET
}


# ── the controller side: provision sends the lists the node checks ──────────

PROVISION = (REPO / "noo-cli/src/commands/provision.rs").read_text()


def test_the_controller_and_the_applier_hold_the_same_kinds() -> None:
    rust = re.search(r'const LINUX_RELEASE_KINDS: &\[&str\] = &\[(.*?)\];', PROVISION, re.S)
    assert rust
    shell = re.search(r'^RELEASE_LISTED_KINDS="([^"]*)"$', TEXT, re.M)
    assert shell
    assert sorted(re.findall(r'"([^"]+)"', rust.group(1))) == sorted(shell.group(1).split() + ["agent-binary"])


def test_provision_attaches_the_lists_after_every_payload_and_before_signing() -> None:
    body = PROVISION[PROVISION.index("pub fn cluster_provision("):]
    body = body[:body.index("\n}\n")]
    at = body.index("attach_release_proof(")
    for step in ("base_bundle_files(", "attach_applier_and_fetcher(", "attach_hostd(", "attach_cli(",
                 "attach_harness(", "drop_binaries_the_node_already_runs(", "attach_nats_credential("):
        assert body.index(step) < at, step
    assert at < body.index("sign_bundle(")


def test_every_other_bundle_carrying_the_applier_carries_the_lists() -> None:
    sub = (REPO / "noo-cli/src/commands/cluster_provision_subprocess.rs").read_text()
    assert 'if kind == "applier" {\n                let proof = crate::commands::provision::release_proof_for(g, &files)?;' in sub
    sec = (REPO / "noo-cli/src/commands/security_local.rs").read_text()
    push = sec[sec.index("fn build_signed_cert_bundle("):]
    push = push[:push.index("\n}\n")]
    applier = push.index('payloads.push(("applier".to_string()')
    assert push.index("cached_release_proof(&applier)") < applier, "a cert push carries the applier without its list"
