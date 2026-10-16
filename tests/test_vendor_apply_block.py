# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""i83 E1e: the Linux applier installs the vendor CLI the controller staged.

The `vendor_install` block of scripts/noo-apply.sh is lifted out between its
markers and run unprivileged against a temp root (VENDOR_ROOT / VENDOR_BIN
redirected, VENDOR_OWN=0), with fake artefacts and manifests in the exact
layout noo-cli's `cluster_vendor::manifest_text` writes (one key per line,
which is also `json.dumps(indent=2)`). The wrapper text it writes is pinned
here to the same strings `cluster_vendor::wrapper_script`'s tests pin, so the
Mac and Linux wrappers cannot drift.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
ELF = b"\x7fELF" + b"\x00" * 60


def block() -> str:
    m = re.search(r"# BEGIN vendor_install\n(.*?)# END vendor_install", APPLIER.read_text(), re.S)
    assert m, "vendor_install is not delimited in noo-apply.sh"
    return m.group(1)


def tgz(members: dict[str, bytes], mode: str = "w:gz", top_symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            t.addfile(info, io.BytesIO(data))
        for name, target in (top_symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            t.addfile(info)
    return buf.getvalue()


def manifest(**kv: str | None) -> str:
    return json.dumps(kv, indent=2) + "\n"


def cli_manifest(payload: bytes, name: str, version: str, entry: str, unpack: str = "tgz",
                 fmt: str = "tarball", runtime: str | None = None, runtime_version: str | None = None) -> str:
    return manifest(kind=name, name=name, version=version, sha256=hashlib.sha256(payload).hexdigest(),
                    format=fmt, unpack=unpack, entry=entry, runtime=runtime, runtime_version=runtime_version)


def stage(tmp: Path, files: dict[str, bytes | str]) -> Path:
    d = tmp / "files"
    if d.exists():
        for f in d.iterdir():
            f.unlink()
    d.mkdir(exist_ok=True)
    for k, v in files.items():
        (d / k).write_bytes(v.encode() if isinstance(v, str) else v)
    return d


def run(tmp: Path, files_dir: Path, func: str = "apply") -> subprocess.CompletedProcess:
    body = {
        "apply": f'vendor_check "{files_dir}" || exit $?\nvendor_apply "{files_dir}" || exit $?',
        "check": f'vendor_check "{files_dir}" || exit $?',
    }[func]
    script = f"""set -eu
logger() {{ :; }}
binary_shas=""; applied=""
note_binary_sha() {{ binary_shas="$binary_shas $1=$(sha256sum "$2" | awk '{{print $1}}')"; }}
{block()}
VENDOR_ROOT="{tmp}/opt/noo/vendor"; VENDOR_BIN="{tmp}/usr/local/bin"; VENDOR_OWN=0
mkdir -p "$VENDOR_BIN"
{body}
echo "applied:$applied"
echo "binary-sha:$binary_shas"
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def test_a_native_cli_installs_with_a_wrapper_and_is_idempotent(tmp_path: Path) -> None:
    art = tgz({"copilot": ELF})
    d = stage(tmp_path, {"vendor-cli": art, "vendor-cli-manifest": cli_manifest(art, "copilot", "1.0.0", "copilot")})
    r = run(tmp_path, d)
    assert r.returncode == 0, r.stderr
    root = tmp_path / "opt/noo/vendor/copilot/1.0.0"
    assert (root / "copilot").read_bytes() == ELF
    assert (root / ".noo-sha256").read_text().strip() == hashlib.sha256(art).hexdigest()
    wrapper = tmp_path / "usr/local/bin/copilot"
    assert wrapper.stat().st_mode & 0o777 == 0o755
    assert wrapper.read_text() == (
        "#!/bin/sh\n"
        "# noomesh vendor wrapper: copilot 1.0.0, staged by the controller; do not edit\n"
        f'exec "{tmp_path}/opt/noo/vendor/copilot/1.0.0/copilot" "$@"\n'
    )
    assert "applied: vendor-cli\n" in r.stdout
    assert "vendor-cli: copilot 1.0.0 installed" in r.stdout
    assert f"vendor-cli={hashlib.sha256(art).hexdigest()}" in r.stdout
    # Same bundle again: a no-op, said so.
    r = run(tmp_path, d)
    assert r.returncode == 0, r.stderr
    assert "applied: vendor-cli=unchanged\n" in r.stdout
    assert "unchanged — already installed, nothing to do" in r.stdout
    assert not list((tmp_path / "usr/local/bin").glob(".*.next"))


def test_a_new_version_replaces_the_wrapper_and_prunes_the_old(tmp_path: Path) -> None:
    a1 = tgz({"bin/codex": ELF})
    d = stage(tmp_path, {"vendor-cli": a1, "vendor-cli-manifest": cli_manifest(a1, "codex", "0.1.0", "bin/codex")})
    assert run(tmp_path, d).returncode == 0
    a2 = tgz({"bin/codex": ELF + b"v2"})
    d = stage(tmp_path, {"vendor-cli": a2, "vendor-cli-manifest": cli_manifest(a2, "codex", "0.2.0", "bin/codex")})
    r = run(tmp_path, d)
    assert r.returncode == 0, r.stderr
    vd = tmp_path / "opt/noo/vendor/codex"
    assert sorted(p.name for p in vd.iterdir()) == ["0.2.0"]
    assert "/codex/0.2.0/bin/codex" in (tmp_path / "usr/local/bin/codex").read_text()


def test_a_single_binary_unpack_none(tmp_path: Path) -> None:
    d = stage(tmp_path, {"vendor-cli": ELF,
                         "vendor-cli-manifest": cli_manifest(ELF, "claude", "2.0.0", "claude", unpack="none", fmt="binary")})
    r = run(tmp_path, d)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "opt/noo/vendor/claude/2.0.0/claude").read_bytes() == ELF


def test_a_runtime_is_flattened_put_first_on_path_and_runs_a_js_entry(tmp_path: Path) -> None:
    fake_node = b'#!/bin/sh\necho "node-ran $*"\n'
    rt = tgz({"node-v22.11.0-linux-x64/bin/node": fake_node, "node-v22.11.0-linux-x64/LICENSE": b"x"}, mode="w:xz")
    cli = tgz({"package/index.js": b"console.log(1)\n"})
    files = {
        "vendor-runtime": rt,
        "vendor-runtime-manifest": manifest(kind="runtime", name="node", version="22.11.0",
                                            sha256=hashlib.sha256(rt).hexdigest(), unpack="tar.xz", bin_dir="bin"),
        "vendor-cli": cli,
        "vendor-cli-manifest": cli_manifest(cli, "copilot", "0.0.339", "package/index.js", fmt="npm-tarball",
                                            runtime="node", runtime_version="22.11.0"),
    }
    r = run(tmp_path, stage(tmp_path, files))
    assert r.returncode == 0, r.stderr
    v = f"{tmp_path}/opt/noo/vendor"
    assert (tmp_path / "opt/noo/vendor/node/22.11.0/bin/node").exists(), "the top-level directory is flattened"
    wrapper = tmp_path / "usr/local/bin/copilot"
    assert wrapper.read_text() == (
        "#!/bin/sh\n"
        "# noomesh vendor wrapper: copilot 0.0.339 on node 22.11.0, staged by the controller; do not edit\n"
        f'PATH="{v}/node/22.11.0/bin:$PATH"\n'
        "export PATH\n"
        f'exec "{v}/node/22.11.0/bin/node" "{v}/copilot/0.0.339/package/index.js" "$@"\n'
    )
    out = subprocess.run([str(wrapper), "-p", "hi"], capture_output=True, text=True)
    assert out.stdout.strip() == f"node-ran {v}/copilot/0.0.339/package/index.js -p hi"
    assert "applied: vendor-runtime vendor-cli\n" in r.stdout
    # The CLI alone later (runtime unchanged, not carried): it finds the runtime on disk.
    cli2 = tgz({"package/index.js": b"console.log(2)\n"})
    r = run(tmp_path, stage(tmp_path, {
        "vendor-cli": cli2,
        "vendor-cli-manifest": cli_manifest(cli2, "copilot", "0.0.340", "package/index.js", fmt="npm-tarball",
                                            runtime="node", runtime_version="22.11.0")}))
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "opt/noo/vendor/node/22.11.0").is_dir(), "a runtime a wrapper names is never pruned"


def test_a_cli_whose_runtime_is_nowhere_is_refused(tmp_path: Path) -> None:
    cli = tgz({"package/index.js": b"x"})
    r = run(tmp_path, stage(tmp_path, {
        "vendor-cli": cli,
        "vendor-cli-manifest": cli_manifest(cli, "copilot", "1.0.0", "package/index.js", runtime="node",
                                            runtime_version="9.9.9")}))
    assert r.returncode == 65 and "neither this bundle nor this node carries" in r.stderr


def test_a_payload_that_does_not_hash_to_its_manifest_is_refused_before_anything(tmp_path: Path) -> None:
    art = tgz({"copilot": ELF})
    d = stage(tmp_path, {"vendor-cli": art + b"tampered",
                         "vendor-cli-manifest": cli_manifest(art, "copilot", "1.0.0", "copilot")})
    r = run(tmp_path, d, "check")
    assert r.returncode == 65 and "does not hash" in r.stderr
    assert not (tmp_path / "opt").exists()


def test_a_payload_without_its_manifest_is_refused(tmp_path: Path) -> None:
    r = run(tmp_path, stage(tmp_path, {"vendor-cli": ELF}), "check")
    assert r.returncode == 65 and "must ride together" in r.stderr


def test_values_that_would_escape_or_shadow_are_refused(tmp_path: Path) -> None:
    art = tgz({"copilot": ELF})
    for kw, why in [
        ({"entry": "../../etc/passwd"}, "entry is not a plain relative path"),
        ({"entry": "/usr/bin/id"}, "entry is not a plain relative path"),
        ({"name": "noo-gateway"}, "would shadow a noomesh binary"),
        ({"name": "node"}, "may not be named node"),
        ({"version": "1.0;id"}, "is not a plain version"),
        ({"unpack": "rar"}, "is not tgz, tar.xz, zip or none"),
    ]:
        fields = json.loads(cli_manifest(art, "copilot", "1.0.0", "copilot"))
        fields.update(kw)
        r = run(tmp_path, stage(tmp_path, {"vendor-cli": art, "vendor-cli-manifest": manifest(**fields)}), "check")
        assert r.returncode == 65 and why in r.stderr, (kw, r.stderr)


def test_a_non_elf_native_entry_is_refused(tmp_path: Path) -> None:
    art = tgz({"copilot": b"#!/bin/sh\necho hi\n"})
    r = run(tmp_path, stage(tmp_path, {"vendor-cli": art,
                                       "vendor-cli-manifest": cli_manifest(art, "copilot", "1.0.0", "copilot")}))
    assert r.returncode == 65 and "not an ELF executable" in r.stderr
    assert not (tmp_path / "usr/local/bin/copilot").exists()
    assert not (tmp_path / "opt/noo/vendor/copilot/1.0.0").exists()


def test_an_archive_that_climbs_out_is_refused(tmp_path: Path) -> None:
    for art, why in ((tgz({"../escape": ELF, "copilot": ELF}), "outside its own directory"),
                     (tgz({"copilot": ELF}, top_symlinks={"evil": "/etc"}), "absolute symlink")):
        r = run(tmp_path, stage(tmp_path, {"vendor-cli": art,
                                           "vendor-cli-manifest": cli_manifest(art, "copilot", "1.0.0", "copilot")}))
        assert r.returncode == 65 and why in r.stderr, r.stderr
        assert not (tmp_path / "escape").exists() and not (tmp_path / "opt/noo/escape").exists()


def test_the_applier_runs_the_check_before_installing_and_the_step_after() -> None:
    text = APPLIER.read_text()
    check = text.index('vendor_check "$WORK/files" || exit 65')
    # The check runs with the other shape checks, before verify-only's exit
    # (the last point before the first write); the install runs after it.
    verify_only_exit = text.index('if [ "$VERIFY_ONLY" = 1 ]; then', check)
    assert check < verify_only_exit < text.index('vendor_apply "$WORK/files" || exit $?')
    # Production paths: /opt/noo/vendor and /usr/local/bin, root-owned.
    assert re.search(r"^VENDOR_ROOT=/opt/noo/vendor$", block(), re.M)
    assert re.search(r"^VENDOR_BIN=/usr/local/bin$", block(), re.M)
    assert re.search(r"^VENDOR_OWN=1 ", block(), re.M)
