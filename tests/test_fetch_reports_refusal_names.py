# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo-fetch.sh` sends the applier's refusal NAME with its apply report, and
reports a failed decrypt instead of exiting silently.

The real functions are lifted out of the script and run under `sh`:

- `applier_refusal`: the name on the applier's LAST `noo-apply: refusal=`
  line, for the rc the applier exited with only;
- `report` / `report_post`: the body gains `"refusal":"<name>"` on a refusal
  with a well-formed name, and is byte for byte today's body otherwise;
- `decrypt_bundle` / `decrypt_refused`: a decrypt failure is reported under
  its own name, and its sha is recorded in $LAST ONLY when the key was read
  and the ciphertext still does not open with it (a cryptographic mismatch:
  the same answer on every tick). An unreadable key or an I/O error is
  reported but NOT recorded, so the next tick retries.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/noo-fetch.sh"
TEXT = SCRIPT.read_text()
SHA = "a" * 64

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl(1)")


def _fn(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?\n^\}}\n", TEXT, re.S | re.M)
    assert m, f"noo-fetch.sh has no {name}() — this test reads the real function"
    return m.group(0)


def _sh(script: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=60, **kw)


# ── the applier's line ──────────────────────────────────────────────────────

def _applier_refusal(tmp_path: Path, log: str, rc: int) -> str:
    (tmp_path / "apply.log").write_text(log)
    r = _sh(f"set -eu\n{_fn('applier_refusal')}\napplier_refusal {rc} {tmp_path}/apply.log\n")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_the_name_is_the_last_line_for_this_rc(tmp_path: Path) -> None:
    log = ("noo-apply: REFUSED — the bundle is not a readable tar\n"
           "noo-apply: refusal=bundle_shape (exit 65)\n")
    assert _applier_refusal(tmp_path, log, 65) == "bundle_shape"
    # The LAST line wins (a re-exec'd applier prints after the first one).
    two = "noo-apply: refusal=env_shape (exit 65)\nnoo-apply: refusal=unit_shape (exit 65)\n"
    assert _applier_refusal(tmp_path, two, 65) == "unit_shape"


def test_a_line_for_another_rc_or_shape_is_no_name(tmp_path: Path) -> None:
    assert _applier_refusal(tmp_path, "noo-apply: refusal=bundle_shape (exit 65)\n", 77) == ""
    assert _applier_refusal(tmp_path, 'noo-apply: refusal=x","rc":0 (exit 65)\n', 65) == ""
    assert _applier_refusal(tmp_path, "noo-apply: refusal=Bundle (exit 65)\n", 65) == ""
    assert _applier_refusal(tmp_path, "x noo-apply: refusal=bundle_shape (exit 65)\n", 65) == "", "anchored at column 1"
    assert _applier_refusal(tmp_path, "noo-apply: refusal=bundle_shape (exit 65) more\n", 65) == ""
    assert _applier_refusal(tmp_path, "noo-apply: REFUSED — old applier, no name\n", 65) == ""


# ── the report body ─────────────────────────────────────────────────────────

def _report_body(tmp_path: Path, rc: int, name: str | None) -> str:
    calls = tmp_path / "curl.calls"
    calls.unlink(missing_ok=True)
    (tmp_path / "apply.log").write_text("noo-apply: something\n")
    setname = "" if name is None else f"NOO_REFUSAL='{name}'"
    harness = f"""
set -eu
TMP={tmp_path}; NODE=node_a; SUM={SHA}; URL=https://ctl.example:8080; TLS=""
{setname}
birth_proof() {{ printf '%s' '1700000000.c2ln'; }}
node_tls() {{ return 1; }}
node_bearer() {{ return 1; }}
curl() {{
    for _a in "$@"; do printf '%s\\n' "$_a" >> {calls}; done
    printf '%s' 200
}}
{_fn('refusal_ok')}
{_fn('report')}
{_fn('report_post')}
report {rc}
"""
    r = _sh(harness)
    assert r.returncode == 0, r.stderr
    argv = calls.read_text().splitlines()
    return argv[argv.index("-d") + 1]


def test_a_refusal_carries_its_name(tmp_path: Path) -> None:
    body = json.loads(_report_body(tmp_path, 65, "bundle_shape"))
    assert body == {"sha": SHA, "rc": 65, "msg": "noo-apply: something ", "refusal": "bundle_shape"}


def test_a_success_body_is_unchanged(tmp_path: Path) -> None:
    raw = _report_body(tmp_path, 0, "bundle_shape")
    assert raw == f'{{"sha":"{SHA}","rc":0,"msg":"noo-apply: something "}}', raw
    raw = _report_body(tmp_path, 65, None)
    assert raw == f'{{"sha":"{SHA}","rc":65,"msg":"noo-apply: something "}}', raw


@pytest.mark.parametrize("name", ['x","rc":0', "Bundle", "9x", "a b", "a" * 49, "bundle-shape", ""])
def test_a_malformed_name_never_reaches_the_body(tmp_path: Path, name: str) -> None:
    raw = _report_body(tmp_path, 65, name)
    body = json.loads(raw)
    assert body["rc"] == 65 and "refusal" not in body, raw


def test_a_48_char_name_is_the_longest(tmp_path: Path) -> None:
    assert json.loads(_report_body(tmp_path, 65, "a" * 48))["refusal"] == "a" * 48


# ── decrypt failures: reported; recorded only for a mismatch ────────────────

def _keypair(d: Path, name: str) -> tuple[Path, Path]:
    key, crt = d / f"{name}.key", d / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                    "-keyout", str(key), "-out", str(crt), "-subj", f"/CN=noo-birth-{name}"],
                   check=True, capture_output=True)
    return key, crt


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("birth")
    a_key, a_crt = _keypair(d, "a")
    b_key, _ = _keypair(d, "b")
    plain = d / "bundle.tar"
    # A real bundle is gzip (a controller >= 0.6.5 gzips before encrypting).
    plain.write_bytes(gzip.compress(b"signed tar stands here\n" * 50))
    blob = d / "blob"
    subprocess.run(["openssl", "smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
                    "-in", str(plain), "-out", str(blob), str(a_crt)], check=True, capture_output=True)
    return {"a": a_key, "b": b_key, "crt": a_crt, "blob": blob, "plain": plain}


def _decrypt(tmp_path: Path, key: Path, blob: Path, *, out_is_dir: bool = False,
             sum_: str | None = None, shim: str = "") -> tuple[int, dict[str, str], list[str]]:
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    (tmp / "blob").write_bytes(blob.read_bytes())
    if out_is_dir:
        (tmp / "bundle.tar").mkdir()
    last = tmp_path / "last-bundle.sha256"
    reports = tmp_path / "reports"
    s = sum_ or hashlib.sha256(blob.read_bytes()).hexdigest()
    harness = f"""
set -eu
TMP={tmp}; KEY={key}; LAST={last}; SUM={s}; NOO_REFUSAL=""
report() {{ echo "rc=$1 name=$NOO_REFUSAL" >> {reports}; }}
{_fn('plaintext_is_bundle')}
{shim}
{_fn('decrypt_bundle')}
{_fn('decrypt_refused')}
if decrypt_bundle; then echo DECRYPTED; else
    decrypt_refused "$?"
    exit 1
fi
"""
    r = _sh(harness)
    state = {"last": last.read_text().strip() if last.exists() else "",
             "stdout": r.stdout, "stderr": r.stderr}
    return r.returncode, state, reports.read_text().splitlines() if reports.exists() else []


def test_the_birth_key_opens_its_bundle(tmp_path: Path, keys: dict[str, Path]) -> None:
    rc, st, rep = _decrypt(tmp_path, keys["a"], keys["blob"])
    assert rc == 0 and "DECRYPTED" in st["stdout"], st
    assert (tmp_path / "tmp/bundle.tar").read_bytes() == keys["plain"].read_bytes()
    assert rep == [] and st["last"] == ""


def test_another_key_is_a_mismatch_reported_and_recorded(tmp_path: Path, keys: dict[str, Path]) -> None:
    rc, st, rep = _decrypt(tmp_path, keys["b"], keys["blob"])
    assert rc == 1, st
    assert rep == ["rc=65 name=bundle_decrypt_failed"], (rep, st)
    assert st["last"] == hashlib.sha256(keys["blob"].read_bytes()).hexdigest(), "a mismatch must stop the retries"
    assert "DECRYPT FAILED" in st["stderr"] and "recorded" in st["stderr"]
    log = (tmp_path / "tmp/apply.log").read_text()
    assert log.startswith("noo-fetch: DECRYPT FAILED") and "does not decrypt" in log, log


@pytest.mark.parametrize("what", ["garbage", "missing", "empty"])
def test_an_unreadable_key_is_reported_and_not_recorded(tmp_path: Path, keys: dict[str, Path], what: str) -> None:
    key = tmp_path / "birth.key"
    if what == "garbage":
        key.write_text("not a key\n")
    elif what == "empty":
        key.write_text("")
    rc, st, rep = _decrypt(tmp_path, key, keys["blob"])
    assert rc == 1, st
    assert rep == ["rc=78 name=birth_key_unreadable"], (rep, st)
    assert st["last"] == "", "an unreadable key says nothing about the bundle: the next tick must retry"


def test_an_output_write_error_is_reported_and_not_recorded(tmp_path: Path, keys: dict[str, Path]) -> None:
    rc, st, rep = _decrypt(tmp_path, keys["a"], keys["blob"], out_is_dir=True)
    assert rc == 1, st
    assert rep == ["rc=73 name=bundle_decrypt_io"], (rep, st)
    assert st["last"] == "", "an I/O error says nothing about the bundle: the next tick must retry"


# What OpenSSL does about 1 time in 256 with a wrong RSA key: its padding-
# oracle defence carries on with a random key, AES-CBC's padding happens to
# validate, and `smime -decrypt` exits 0 having written garbage. Forced here,
# so the test does not depend on that chance (it once made this suite flaky).
GARBAGE_DECRYPT = r"""
openssl() {
    if [ "$1" = smime ]; then
        _o=""; _prev=""
        for _a in "$@"; do [ "$_prev" = -out ] && _o="$_a"; _prev="$_a"; done
        printf 'not a bundle at all, just bytes\n' > "$_o"
        return 0
    fi
    command openssl "$@"
}
"""


def test_a_wrong_key_that_decrypts_to_garbage_is_a_mismatch_not_a_bundle(tmp_path: Path, keys: dict[str, Path]) -> None:
    rc, st, rep = _decrypt(tmp_path, keys["b"], keys["blob"], shim=GARBAGE_DECRYPT)
    assert rc == 1 and "DECRYPTED" not in st["stdout"], st
    assert rep == ["rc=65 name=bundle_decrypt_failed"], (rep, st)
    assert st["last"] == hashlib.sha256(keys["blob"].read_bytes()).hexdigest(), "a mismatch must stop the retries"
    assert not (tmp_path / "tmp/bundle.check").exists()


def test_the_bundle_shape_is_gzip_or_tar(tmp_path: Path) -> None:
    g = tmp_path / "g"; g.write_bytes(gzip.compress(b"x"))
    t = tmp_path / "t"; t.write_bytes(b"\0" * 257 + b"ustar\0" + b"\0" * 250)
    junk = tmp_path / "j"; junk.write_bytes(b"not a bundle at all, just bytes\n")
    for f, ok in ((g, True), (t, True), (junk, False)):
        r = _sh(f"{_fn('plaintext_is_bundle')}\nplaintext_is_bundle {f}")
        assert (r.returncode == 0) is ok, (f.name, r)


def test_a_blob_that_no_longer_hashes_to_its_sum_is_io_not_a_mismatch(tmp_path: Path, keys: dict[str, Path]) -> None:
    rc, st, rep = _decrypt(tmp_path, keys["b"], keys["blob"], sum_="0" * 64)
    assert rep == ["rc=73 name=bundle_decrypt_io"], (rep, st)
    assert st["last"] == ""


def test_each_staging_is_a_new_ciphertext(tmp_path: Path, keys: dict[str, Path]) -> None:
    """What un-sticks a recorded decrypt failure: the controller encrypts every
    staging afresh, so the same bundle staged again is a new sha (≠ $LAST)."""
    outs = []
    for i in range(2):
        out = tmp_path / f"blob{i}"
        subprocess.run(["openssl", "smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
                        "-in", str(keys["plain"]), "-out", str(out), str(keys["crt"])], check=True, capture_output=True)
        outs.append(hashlib.sha256(out.read_bytes()).hexdigest())
    assert outs[0] != outs[1]
    enc = (ROOT / "noo-cli/src/commands/provision.rs").read_text()
    assert '.args(["smime", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER", "-in"])' in enc


# ── the main flow ───────────────────────────────────────────────────────────

def test_the_main_flow_reports_a_decrypt_failure_after_report_exists() -> None:
    call = TEXT.index("if decrypt_bundle; then :; else")
    assert TEXT.index("\nreport() {") < call and TEXT.index("\ndecrypt_refused() {") < call
    assert call < TEXT.index("if unwrap_gzip; then"), "decrypt precedes the gzip unwrap"
    assert re.search(r'if decrypt_bundle; then :; else\n\s+decrypt_refused "\$\?"\n\s+exit 1\n', TEXT)
    # $LAST is written in the decrypt path only under DECRYPT_RECORD.
    body = _fn("decrypt_refused")
    assert body.count("> \"$LAST\"") == 1
    assert 'if [ "$DECRYPT_RECORD" = 1 ]; then printf \'%s\\n\' "$SUM" > "$LAST"; fi' in body


def test_the_applier_name_is_read_before_the_refusal_is_reported() -> None:
    tail = TEXT[TEXT.index('if /usr/local/bin/noo-apply "$TMP/bundle.tar"'):]
    assert tail.index('NOO_REFUSAL="$(applier_refusal "$rc" "$TMP/apply.log")"') < tail.index('report "$rc"')
    # The gzip refusals name themselves.
    gz = _fn("unwrap_gzip")
    assert "NOO_REFUSAL=tool_missing; return 69" in gz and "NOO_REFUSAL=bundle_gzip_failed; return 69" in gz
