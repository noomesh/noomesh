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
    assert "roll to a published release or rc" in line or "(noo upgrade --stack)" in line, line
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


def _stub(fleet: Fleet, name: str, body: str) -> None:
    f = fleet.tmp / "stub" / name
    f.write_text(body)
    f.chmod(0o755)


def _no_openssl3(fleet: Fleet) -> None:
    """An OpenSSL 1.1.1: no `pkeyutl -rawin`, every other verb the real one."""
    real = subprocess.run(["sh", "-c", "command -v openssl"], capture_output=True, text=True).stdout.strip()
    _stub(fleet, "openssl", f'#!/bin/sh\n[ "$1 $2" = "pkeyutl -help" ] && {{ echo "Usage: pkeyutl"; exit 1; }}\n'
                            f'[ "$1" = version ] && {{ echo "OpenSSL 1.1.1f  31 Mar 2020"; exit 0; }}\n'
                            f'[ "$1" = pkeyutl ] && {{ echo "pkeyutl: unknown option -rawin" >&2; exit 1; }}\nexec {real} "$@"\n')


def test_without_openssl3_the_python_fallback_verifies(fleet: Fleet) -> None:
    _no_openssl3(fleet)
    r = fleet.apply(fleet.bundle(dict(PAYLOADS)))
    passed(r)
    assert "verifier=python" in r.stdout, r.stdout


def test_the_python_fallback_refuses_a_wrong_key_and_an_edited_list(fleet: Fleet, tmp_path: Path) -> None:
    _no_openssl3(fleet)
    other = ReleaseKey(tmp_path / "not-the-release")
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    refused(fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, sums_key=other)})),
            "release-sums — its signature does not verify")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    refused(fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, lock_key=other)})),
            "release-lock — its signature does not verify")
    evil = {"hostd-binary": ELF + b"evil"}
    proof = fleet.release_proof({"hostd-binary": PAYLOADS["hostd-binary"]})
    proof["release-sums"] += f"{hashlib.sha256(evil['hostd-binary']).hexdigest()}  noo-hostd-x86_64-unknown-linux-gnu\n".encode()
    refused(fleet.apply(fleet.bundle({**evil, **proof})), "does not verify")


def test_the_embedded_python_verifier_agrees_with_the_repo_script(tmp_path: Path) -> None:
    """Same answers as scripts/verify-release-signature.py, on a good and a bad signature."""
    code = subprocess.run(["bash", "-c", TEXT[TEXT.index('RELEASE_PY_ED25519="$(cat'):TEXT.index("\nPY\n)\"") + 6]
                           + '\nprintf "%s" "$RELEASE_PY_ED25519"'], capture_output=True, text=True, check=True).stdout
    key = ReleaseKey(tmp_path / "k")
    data = tmp_path / "data"
    data.write_bytes(b"deadbeef  noo-apply.sh\n")
    sig = key.sign(data.read_bytes()).decode().strip()
    (tmp_path / "data.sig").write_text(sig + "\n")
    body = sig.removeprefix("noo-sig1.")
    bad = ("B" if body[0] != "B" else "C") + body[1:]
    for b, want in [(body, 0), (bad, 1)]:
        emb = subprocess.run(["python3", "-I", "-c", code, str(data), b, "00" * 32, key.pub_hex]).returncode
        assert emb == want, (b == body, emb)
    script = subprocess.run(["python3", "-I", str(REPO / "scripts/verify-release-signature.py"), "--key", key.pub_hex,
                             str(data), str(tmp_path / "data.sig")]).returncode
    assert script == 0


def test_with_neither_openssl3_nor_python3_root_code_is_refused_and_says_so(fleet: Fleet) -> None:
    _no_openssl3(fleet)
    _stub(fleet, "python3", "#!/bin/sh\nexit 127\n")
    line = refused(fleet.apply(fleet.bundle({"applier": PAYLOADS["applier"]})), "needs OpenSSL 3 or python3")
    assert "applier" in line


# ── the version the list names, and the floor ───────────────────────────────

def test_a_version_text_the_list_does_not_name_is_refused(fleet: Fleet) -> None:
    files = {"fetcher": PAYLOADS["fetcher"]}
    proof = fleet.release_proof(files)
    proof["release-version"] = b"0.6.99\n"
    refused(fleet.apply(fleet.bundle({**files, **proof})), "is not the release the signed list names")


# One step back (operator 2026-11-17): the record keeps the last two finals.
@pytest.mark.parametrize("final,prev,version,ok", [
    ("0.6.28", "0.6.27", "0.6.27", True),        # one final back
    ("0.6.28", "0.6.27", "0.6.26", False),       # two finals back
    ("0.6.28", "0.6.27", "0.6.28", True),
    ("0.6.28", "0.6.27", "0.6.29", True),
    ("0.6.28", "", "0.6.27", False),             # only one final known: nothing older
    ("0.6.28", "0.6.27", "0.6.28-rc.3", True),   # an rc of the current release
    ("0.6.28", "0.6.27", "0.6.29-rc.1", True),   # an rc of the next release
    ("0.6.28", "0.6.27", "0.6.27-rc.9", False),  # an rc older than the previous final
    ("0.6.10", "0.6.9", "0.6.9", True),          # numeric, not string, order
    ("1.0.0", "0.99.99", "0.99.98", False),
    ("", "", "0.1.0", True),                     # nothing recorded yet
])
def test_the_release_floor_steps_back_one_final(fleet: Fleet, final: str, prev: str, version: str, ok: bool) -> None:
    fleet.floor.write_text("# test\n" + (f"release-final {final}\n" if final else "") + (f"release-prev {prev}\n" if prev else ""))
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, version=version)}))
    if ok:
        passed(r)
    else:
        refused(r, "this node is ahead of its controller")


@pytest.mark.parametrize("final,prev,tag,ok", [
    ("v0.6.28", "v0.6.27", "v0.6.27", True), ("v0.6.28", "v0.6.27", "v0.6.26", False),
    ("v0.6.28", "v0.6.27", "stack-v0.6.28", True), ("v0.6.28", "", "v0.6.27", False)])
def test_the_stack_floor_steps_back_one_final(fleet: Fleet, final: str, prev: str, tag: str, ok: bool) -> None:
    fleet.floor.write_text(f"stack-final {final}\n" + (f"stack-prev {prev}\n" if prev else ""))
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, stack=tag)}))
    if ok:
        passed(r)
    else:
        refused(r, "this node is ahead of its controller")


def test_a_floor_record_that_is_not_a_version_refuses(fleet: Fleet) -> None:
    fleet.floor.write_text("release-final $(id)\n")
    refused(fleet.apply(fleet.bundle({"fetcher": PAYLOADS["fetcher"]})), "is not a version")


def _floor_fns() -> str:
    block = TEXT[TEXT.index("# BEGIN release_check"):TEXT.index("# END release_check")]
    return block


def _write_floor(floor: Path, *calls: tuple[str, str]) -> dict[str, str]:
    script = _floor_fns() + "\n" + "\n".join(f'release_floor_write "{v}" "{s}"' for v, s in calls)
    subprocess.run(["bash", "-c", f"set -eu\nVERIFY_ONLY=0\nRELEASE_FLOOR={floor}\n{script}"], check=True, capture_output=True)
    if not floor.exists():
        return {}
    return dict(l.split(" ", 1) for l in floor.read_text().splitlines() if not l.startswith("#"))


def test_the_record_keeps_the_last_two_finals_and_the_oldest_never_falls(tmp_path: Path) -> None:
    f = tmp_path / "floor"
    assert _write_floor(f, ("0.6.27", "v0.6.27")) == {"release-final": "0.6.27", "stack-final": "v0.6.27"}
    assert _write_floor(f, ("0.6.28", "v0.6.28")) == {"release-final": "0.6.28", "release-prev": "0.6.27",
                                                      "stack-final": "v0.6.28", "stack-prev": "v0.6.27"}
    # One step back, then an rc, then forward: the oldest accepted never moves down.
    rec = _write_floor(f, ("0.6.27", "v0.6.27"), ("0.6.29-rc.1", "v0.6.29-rc.1"))
    assert rec["release-final"] == "0.6.28" and rec["release-prev"] == "0.6.27", rec
    rec = _write_floor(f, ("0.6.29", ""))
    assert rec["release-final"] == "0.6.29" and rec["release-prev"] == "0.6.28", rec
    empty = tmp_path / "nothing-verified"
    assert _write_floor(empty, ("", "")) == {}, "a config-only apply wrote a floor"
    assert _write_floor(empty, ("0.6.27-rc.1", "")) == {}, "an rc moved the record"


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
    assert r.returncode == 75 and "applier generation 1, which has no release check" in r.stderr, (r.stdout, r.stderr)


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
    gate = sub[sub.index('if kind == "applier" || kind == "hostd-binary" {'):]
    gate = gate[:gate.index("files.extend(proof);")]
    assert "node_floor_refusal(&msg" in gate and "release_proof_for(g, &files)?" in gate, gate


def test_the_controller_refuses_a_node_ahead_before_staging() -> None:
    body = PROVISION[PROVISION.index("fn attach_release_proof("):]
    body = body[:body.index("\n}\n")]
    assert body.index("node_floor_refusal(&reported_apply_msg(g, &a.node)") < body.index('files.push(("release-sums"')
    assert 'Some("noo upgrade --stack")' in body
    sec = (REPO / "noo-cli/src/commands/security_local.rs").read_text()
    push = sec[sec.index("fn build_signed_cert_bundle("):]
    push = push[:push.index("\n}\n")]
    applier = push.index('payloads.push(("applier".to_string()')
    assert push.index("cached_release_proof(&applier)") < applier, "a cert push carries the applier without its list"


def test_upgrade_hostd_ships_the_release_asset_with_its_list() -> None:
    sub = (REPO / "noo-cli/src/commands/cluster_provision_subprocess.rs").read_text()
    body = sub[sub.index("pub fn cluster_upgrade_hostd("):]
    body = body[:body.index("\n}\n")]
    assert "cached_release_asset(g, &root, &asset)" in body and "hostd_release_asset(arch)" in body
    assert "build-cross" not in body and "skip_build" not in body, "upgrade-hostd still builds from a checkout"
    assert 'if kind == "applier" || kind == "hostd-binary" {' in sub
    usage = (REPO / "noo-cli/src/usage.rs").read_text()
    assert '(&["cluster", "upgrade-hostd"], "<node>... [-y|--yes|--force]"' in usage


# i940: a node ahead of its controller says so, naming what to roll to.
@pytest.mark.parametrize("record,version,line", [
    ("release-final 0.6.29\nrelease-prev 0.6.28\n", "0.6.27",
     "REFUSED release 0.6.27 — this node is ahead of its controller (it applied 0.6.29 after 0.6.28; the controller staged 0.6.27): "
     "roll the controller to 0.6.28 or later (noo upgrade --stack), then this node takes its bundles again (75)"),
    ("release-final 0.6.28\n", "0.6.27",
     "REFUSED release 0.6.27 — this node is ahead of its controller (it applied 0.6.28; the controller staged 0.6.27): "
     "roll the controller to 0.6.28 or later (noo upgrade --stack), then this node takes its bundles again (75)"),
    ("release-final 0.6.28\nrelease-prev 0.6.27\n", "0.6.27-rc.4",
     "REFUSED release 0.6.27-rc.4 — this node is ahead of its controller (it applied 0.6.28 after 0.6.27; the controller staged 0.6.27-rc.4): "
     "roll the controller to 0.6.28 or later (noo upgrade --stack), then this node takes its bundles again (75)"),
])
def test_a_node_ahead_of_its_controller_names_the_cause(fleet: Fleet, record: str, version: str, line: str) -> None:
    fleet.floor.write_text(record)
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, version=version)}))
    assert r.returncode == 75 and f"noo-apply: {line}" in r.stderr.splitlines(), r.stderr


def test_a_stack_ahead_names_the_cause(fleet: Fleet) -> None:
    fleet.floor.write_text("stack-final v0.6.29\nstack-prev v0.6.28\n")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    r = fleet.apply(fleet.bundle({**files, **fleet.release_proof(files, stack="v0.6.27")}))
    assert ("noo-apply: REFUSED stack v0.6.27 — this node is ahead of its controller (it applied v0.6.29 after v0.6.28; "
            "the controller staged v0.6.27): roll the controller to v0.6.28 or later (noo upgrade --stack), then this node "
            "takes its bundles again (75)") in r.stderr.splitlines(), r.stderr


def test_the_shell_and_rust_ahead_lines_are_the_same_words() -> None:
    rs = (REPO / "noo-cli/src/release_gate.rs").read_text()
    for frag in ["this node is ahead of its controller (it applied ", "; the controller staged ",
                 " or later (noo upgrade --stack), then this node takes its bundles again ("]:
        assert frag in TEXT and frag in rs, frag


# ── every release vouches for its previous final (`@v<prev>` rows) ──────────

def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_a_one_back_agent_row_is_accepted_and_moves_nothing(fleet: Fleet) -> None:
    fleet.floor.write_text("stack-final v0.6.28\nstack-prev v0.6.27\n")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    proof = fleet.release_proof(files, stack="v0.6.28", unlisted_kinds=("agent-binary",),
                                extra_lock_rows=(f"# node-agent-sha256@v0.6.27 linux/amd64 {_sha(PAYLOADS['agent-binary'])}",))
    r = fleet.apply(fleet.bundle({**files, **proof}))
    passed(r)
    assert "stack=v0.6.27" in r.stdout, r.stdout


def test_a_two_back_agent_row_is_refused_as_ahead(fleet: Fleet) -> None:
    fleet.floor.write_text("stack-final v0.6.29\nstack-prev v0.6.28\n")
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    proof = fleet.release_proof(files, stack="v0.6.28", unlisted_kinds=("agent-binary",),
                                extra_lock_rows=(f"# node-agent-sha256@v0.6.27 linux/amd64 {_sha(PAYLOADS['agent-binary'])}",))
    r = fleet.apply(fleet.bundle({**files, **proof}))
    assert r.returncode == 75 and ("REFUSED stack v0.6.27 — this node is ahead of its controller (it applied v0.6.29 after v0.6.28; "
                                   "the controller staged v0.6.27)") in r.stderr, r.stderr


@pytest.mark.parametrize("final,prev,ok", [("0.6.28", "0.6.27", True), ("0.6.29", "0.6.28", False)])
def test_a_previous_release_hostd_row_is_judged_as_that_release(fleet: Fleet, final: str, prev: str, ok: bool) -> None:
    fleet.floor.write_text(f"release-final {final}\nrelease-prev {prev}\n")
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    proof = fleet.release_proof(files, version="0.6.28", unlisted_kinds=("hostd-binary",),
                                extra_sums_rows=(f"{_sha(PAYLOADS['hostd-binary'])}  noo-hostd-x86_64-unknown-linux-gnu@v0.6.27",))
    r = fleet.apply(fleet.bundle({**files, **proof}))
    if ok:
        passed(r)
        assert "release-check: verified release=0.6.27 " in r.stdout, r.stdout
    else:
        assert r.returncode == 75 and "REFUSED release 0.6.27 — this node is ahead of its controller" in r.stderr, r.stderr


def test_a_previous_release_row_never_carries_a_generation_1_applier(fleet: Fleet) -> None:
    old = re.sub(rb"(?m)^NOO_APPLY_GENERATION=\d+$", b"NOO_APPLY_GENERATION=1", APPLIER.read_bytes())
    files = {"applier": old}
    proof = fleet.release_proof(files, unlisted_kinds=("applier",), extra_sums_rows=(f"{_sha(old)}  noo-apply.sh@v0.6.26",))
    refused(fleet.apply(fleet.bundle({**files, **proof})), "applier generation 1, which has no release check")


@pytest.mark.parametrize("rows,why", [
    (("{h}  noo-hostd-x86_64-unknown-linux-gnu@v0.6.26", "{z}  noo-fetch.sh@v0.6.25"), "more than one previous release"),
    (("{h}  noo-hostd-x86_64-unknown-linux-gnu@v0.6.27",), "not a final older than 0.6.27"),
    (("{h}  noo-hostd-x86_64-unknown-linux-gnu@v0.6.28",), "not a final older than 0.6.27"),
    (("{h}  noo-hostd-x86_64-unknown-linux-gnu@v0.6.26-rc.2",), "name an rc"),
    (("{h}  noo-hostd-x86_64-unknown-linux-gnu@vbogus",), "not a final older than"),
], ids=["two-tags", "same-release", "newer", "rc", "not-a-version"])
def test_a_list_names_one_previous_final_only(fleet: Fleet, rows: tuple[str, ...], why: str) -> None:
    files = {"hostd-binary": PAYLOADS["hostd-binary"]}
    rows = tuple(r.format(h=_sha(PAYLOADS["hostd-binary"]), z="0" * 64) for r in rows)
    proof = fleet.release_proof(files, unlisted_kinds=("hostd-binary",), extra_sums_rows=rows)
    refused(fleet.apply(fleet.bundle({**files, **proof})), why)


def test_a_lock_names_one_previous_final_only(fleet: Fleet) -> None:
    files = {"agent-binary": PAYLOADS["agent-binary"]}
    a = _sha(PAYLOADS["agent-binary"])
    proof = fleet.release_proof(files, stack="v0.6.27", unlisted_kinds=("agent-binary",),
                                extra_lock_rows=(f"# node-agent-sha256@v0.6.26 linux/amd64 {a}", f"# node-agent-sha256@v0.6.25 linux/arm64 {a}"))
    refused(fleet.apply(fleet.bundle({**files, **proof})), "release-lock — it vouches for more than one previous release")


# ── the first roll's applier-only bootstrap (rc.2 UPGRADE cell, A3) ─────────
# An older applier installs this applier from an applier-only bundle and
# re-execs it on the same bundle, which can carry no release list. When the
# bundle's ONE payload is byte-identical to the installed applier there is
# nothing to install: exit 0, one plain line, no REFUSED. Anything else is
# still checked: a DIFFERENT applier with no list is refused
# (test_root_code_without_any_release_list_is_refused[applier]).

def _installed_is(fleet: Fleet, body: bytes) -> None:
    fleet.self_path.write_bytes(body)


def test_an_applier_only_bundle_of_the_installed_applier_is_a_clean_no_op(fleet: Fleet) -> None:
    body = PAYLOADS["applier"]
    _installed_is(fleet, body)
    r = fleet.apply(fleet.bundle({"applier": body}, release=False))
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert "applier-only bundle: this applier is already installed" in r.stdout, r.stdout
    assert hashlib.sha256(body).hexdigest() in r.stdout
    assert "REFUSED" not in r.stdout + r.stderr, r.stderr


def test_an_applier_only_bundle_of_a_different_applier_is_still_refused(fleet: Fleet) -> None:
    _installed_is(fleet, PAYLOADS["applier"] + b"\n# the installed one differs\n")
    line = refused(fleet.apply(fleet.bundle({"applier": PAYLOADS["applier"]}, release=False)), "no release-signed list")
    assert "applier" in line


def test_the_installed_applier_beside_another_kind_is_still_checked(fleet: Fleet) -> None:
    # Not applier-only: the identical applier plus root code is not exempt.
    body = PAYLOADS["applier"]
    _installed_is(fleet, body)
    line = refused(fleet.apply(fleet.bundle({"applier": body, "fetcher": PAYLOADS["fetcher"]}, release=False)),
                   "no release-signed list")
    assert "fetcher" in line or "applier" in line
