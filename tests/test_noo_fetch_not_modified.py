# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo-fetch.sh` asks for the bundle with If-None-Match and treats 304 as "unchanged".

Measured on a live node: every third timer tick downloaded the whole bundle
(~400 MiB) only to find its sha256 equal to last-bundle.sha256. The controller
now sends `ETag: "<sha256 of the ciphertext>"` and answers 304 with no body to
`If-None-Match: "<that sha>"`.

The real `fetch_bundle` function is lifted out of the script and run under `sh`
with a fake `curl` on PATH that records its argv and answers a chosen code:

- an old controller (ignores the header, 200 + same bytes) -> code 200, body written;
- a controller that honours it                             -> code 304, no body;
- a changed bundle                                         -> code 200, new bytes;
- no / malformed last-bundle.sha256                        -> no If-None-Match at all.

The main flow cannot run here (controller, birth key), so the 304 branch is a
shape guard on the script text.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/noo-fetch.sh"
SHA = "ab" * 32


def _function() -> str:
    m = re.search(r"^fetch_bundle\(\) \{\n.*?^\}\n", SCRIPT.read_text(), re.S | re.M)
    assert m, "noo-fetch.sh has no fetch_bundle() — this test reads the real function"
    return m.group(0)


FAKE_CURL = """#!/bin/sh
printf '%s\\n' "$@" > "$FAKE_ARGV"
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "-o" ] && out="$2"
    shift
done
[ -n "$FAKE_BODY" ] && printf '%s' "$FAKE_BODY" > "$out"
printf '%s' "$FAKE_CODE"
"""


def _run(tmp_path: Path, *, last: str | None, code: str, body: str = ""):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    curl = bindir / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(0o755)
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    lastf = tmp_path / "last-bundle.sha256"
    if last is not None:
        lastf.write_text(last)
    argv = tmp_path / "argv"
    harness = (
        f"set -u\nTMP={tmp}\nLAST={lastf}\nTLS=''\nURL=https://ctl\nNODE=n1\n"
        f"{_function()}\nfetch_bundle\nprintf '%s' \"$CODE\" > {tmp_path}/code\n"
    )
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "FAKE_ARGV": str(argv), "FAKE_CODE": code, "FAKE_BODY": body}
    r = subprocess.run(["/bin/sh", "-c", harness], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    args = argv.read_text().splitlines()
    blob = tmp / "blob"
    return (tmp_path / "code").read_text(), args, (blob.read_bytes() if blob.exists() else None), lastf


def test_old_controller_ignores_the_header_and_sends_the_same_bytes(tmp_path):
    code, args, blob, _ = _run(tmp_path, last=SHA + "\n", code="200", body="CIPHERTEXT")
    assert code == "200" and blob == b"CIPHERTEXT"
    assert f'If-None-Match: "{SHA}"' in args


def test_304_sends_the_exact_etag_and_writes_no_body(tmp_path):
    code, args, blob, lastf = _run(tmp_path, last=SHA + "\n", code="304")
    assert code == "304"
    assert blob is None or blob == b""
    i = args.index(f'If-None-Match: "{SHA}"')
    assert args[i - 1] == "-H"
    assert lastf.read_text() == SHA + "\n"
    assert args[-1] == "https://ctl/bootstrap/bundle/n1"


def test_changed_bundle_is_a_200_with_new_bytes(tmp_path):
    code, _, blob, _ = _run(tmp_path, last=SHA + "\n", code="200", body="NEW-BYTES")
    assert code == "200" and blob == b"NEW-BYTES"


def test_no_last_sends_no_header(tmp_path):
    code, args, blob, _ = _run(tmp_path, last=None, code="200", body="X")
    assert code == "200" and blob == b"X"
    assert not any("If-None-Match" in a for a in args)


def test_malformed_last_sends_no_header(tmp_path):
    for n, bad in enumerate(["", "short\n", SHA.upper() + "\n", SHA[:-1] + "g\n", SHA + "00\n", SHA + "\nextra\n"]):
        d = tmp_path / f"c{n}"
        d.mkdir()
        _, args, _, _ = _run(d, last=bad, code="200", body="X")
        assert not any("If-None-Match" in a for a in args), bad


# ── shape guards on the main flow ─────────────────────────────────────

def _branch() -> str:
    src = SCRIPT.read_text()
    m = re.search(r"^    304\)\n(.*?)exit 0 ;;\n", src, re.S | re.M)
    assert m, "noo-fetch.sh has no 304) branch"
    return m.group(0)


def test_304_branch_receipts_with_last_exits_zero_before_any_decrypt():
    src = SCRIPT.read_text()
    b = _branch()
    # The receipt names exactly the sha this request sent, not a re-read of $LAST.
    assert 'SUM="$_inm"' in b
    assert "head -c 64" not in b
    assert 'birth_proof fetch "$SUM"' in b and "/fetched" in b
    assert b.rstrip().endswith("exit 0 ;;")
    assert src.index(b) < src.index("openssl smime -decrypt")
    assert src.index(b) < src.index("/usr/local/bin/noo-apply")
    assert src.index("birth_proof() {") < src.index(b), "receipt signer must exist before the 304 branch"


def test_a_304_to_a_request_without_if_none_match_fails_before_any_receipt():
    b = _branch()
    guard = b.index('if [ -z "$_inm" ]; then')
    assert "exit 1" in b[guard:b.index("fi", guard)]
    assert guard < b.index("birth_proof"), "a 304 nobody asked for must never be receipted"
    assert guard < b.index('SUM="$_inm"')


def test_fetch_bundle_runs_in_the_main_shell_so_the_sent_sha_reaches_the_branch():
    src = SCRIPT.read_text()
    # `CODE="$(fetch_bundle)"` would run it in a subshell and lose $_inm.
    assert re.search(r"^fetch_bundle$", src, re.M)
    assert "$(fetch_bundle" not in src


def test_304_branch_writes_no_state():
    b = _branch()
    for name in ("$LAST", "$EXPECT", "$STATE"):
        for m in re.finditer(re.escape(name), b):
            tail = b[m.end():m.end() + 3]
            head = b[max(0, m.start() - 4):m.start()]
            assert ">" not in head and not tail.startswith("\n>"), f"304 branch writes {name}"
    assert "printf '10" not in b and "rm -f" not in b
    # LAST is only read there (head -c 64), never redirected into.
    assert not re.search(r">\s*\"?\$(LAST|EXPECT|STATE)", b)


def test_304_debug_line_uses_the_journald_debug_prefix():
    b = _branch()
    assert 'echo "<7>noo-fetch: bundle unchanged (304, $SUM)"' in b
    assert ">&2" not in b.split('echo "<7>')[1].split("\n")[0]


def test_conditional_header_only_from_a_64_hex_last():
    f = _function()
    assert "If-None-Match" in f and "[!0-9a-f]" in f
