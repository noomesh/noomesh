# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo-fetch.sh` unwraps a gzip-compressed bundle between decrypt and apply.

A controller at noo-cli >= 0.6.5 gzips bundle.tar before CMS-encrypting it
(AES output does not compress). The real `unwrap_gzip` function is lifted out
of the script and run under `sh` against a staged `bundle.tar`:

- plain tar (no magic)       -> left untouched, rc 0;
- gzip of a tar              -> replaced by the identical tar, rc 0;
- corrupt gzip (magic ok)    -> rc 69, readable reason in apply.log, tar kept;
- gzip absent from PATH      -> rc 69, "not installed" in apply.log.

The last two are what the controller's wait sees as a failed apply with a
reason, instead of `noo-apply` refusing gzip bytes as "not a readable tar".
The main-flow ordering (unwrap BEFORE noo-apply, failure reported via
report()) is a shape guard on the script text: the script cannot be run end to
end here (it needs a controller and a birth key).
"""

from __future__ import annotations

import gzip
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/noo-fetch.sh"


def _function() -> str:
    m = re.search(r"^unwrap_gzip\(\) \{\n.*?^\}\n", SCRIPT.read_text(), re.S | re.M)
    assert m, "noo-fetch.sh has no unwrap_gzip() — this test reads the real function"
    return m.group(0)


def _run(tmp_path: Path, payload: bytes, *, path: str | None = None) -> tuple[int, str, bytes]:
    (tmp_path / "bundle.tar").write_bytes(payload)
    harness = f"set -u\nTMP={tmp_path}\n{_function()}\nunwrap_gzip\n"
    env = {"PATH": path if path is not None else "/usr/bin:/bin"}
    r = subprocess.run(["/bin/sh", "-c", harness], capture_output=True, text=True, env=env)
    log = (tmp_path / "apply.log").read_text() if (tmp_path / "apply.log").exists() else ""
    return r.returncode, log + r.stderr, (tmp_path / "bundle.tar").read_bytes()


TAR = b"manifest\n" * 4000  # stands in for the signed tar: the function never parses it

pytestmark = pytest.mark.skipif(shutil.which("gzip") is None, reason="needs gzip(1)")


def test_plain_tar_passes_through(tmp_path):
    rc, _, out = _run(tmp_path, TAR)
    assert rc == 0 and out == TAR


def test_gzip_is_replaced_by_the_identical_tar(tmp_path):
    rc, _, out = _run(tmp_path, gzip.compress(TAR, 6))
    assert rc == 0 and out == TAR
    assert not (tmp_path / "bundle.tar.plain").exists()


def test_corrupt_gzip_is_a_readable_rc_69(tmp_path):
    bad = gzip.compress(TAR, 6)[:40]  # magic intact, stream truncated
    rc, msg, out = _run(tmp_path, bad)
    assert rc == 69
    assert "could not decompress" in msg
    assert out == bad, "the original bytes must survive a failed decompress"


def test_absent_gzip_is_a_readable_rc_69(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("head", "od", "tr", "tee", "mv", "cat", "echo"):
        found = shutil.which(tool)
        if found:
            (bindir / tool).symlink_to(found)
    assert not (bindir / "gzip").exists()
    rc, msg, _ = _run(tmp_path, gzip.compress(TAR, 6), path=str(bindir))
    assert rc == 69
    assert "gzip is not installed" in msg


def test_main_flow_unwraps_before_the_applier_and_reports_the_refusal():
    """Shape guard: unwrap_gzip runs before noo-apply and a failure goes through report()."""
    text = SCRIPT.read_text()
    call = text.index("if unwrap_gzip; then")
    assert call < text.index("/usr/local/bin/noo-apply \"$TMP/bundle.tar\""), "unwrap must precede the apply"
    assert call > text.index("\nreport() {"), "report() must be defined before the unwrap failure path calls it"
    assert re.search(r'report "\$_grc"\n\s+exit "\$_grc"', text), "a failed unwrap must report its rc and exit non-zero"
    assert '"1f8b"' in text, "gzip is detected by magic bytes, not by a controller hint"
