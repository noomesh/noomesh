# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""install.sh's download() names the real cause and retries only what is
transient (followup i11b).

It used to silence gh, fall back to a plain curl that a private repo always
answers with 404, and silence that too — so a GitHub blip read as "no signed
release manifest" for an asset that was there. These tests drive the real
function from the shipped script against a scripted HTTP server on loopback
and a fake `gh` on PATH: the transport is mocked, not download() itself.
"""

from __future__ import annotations

import http.server
import os
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "noo-cli" / "install.sh"

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="needs curl")


def _helpers() -> str:
    """The helper block of the shipped script, from err() to sha256_of()."""
    text = INSTALL.read_text()
    i = text.index("err() {")
    j = text.index('# Compute the SHA-256 of file "$1"')
    return 'REPO="o/r"\n' + text[i:j]


class _Server:
    """Plays `script[n]` for the n-th request (the last one repeating)."""

    def __init__(self, script: list[tuple[int, dict[str, str], bytes]]) -> None:
        self.hits = 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                status, headers, body = script[min(outer.hits, len(script) - 1)]
                outer.hits += 1
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a: object) -> None:
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def url(self) -> str:
        return f"{self.base}/o/r/releases/download/noo-cli-v1.2.3/noo-x"

    def close(self) -> None:
        self.httpd.shutdown()


def _fake_gh(bindir: Path, outcomes: list[tuple[int, str]]) -> Path:
    """A `gh` that plays outcome n on its n-th run; exit 0 writes the file."""
    lines = [
        "#!/bin/sh",
        'c=$(cat "$0.n" 2>/dev/null || echo 0); c=$((c+1)); echo $c > "$0.n"',
        'out=""; while [ $# -gt 0 ]; do [ "$1" = "-O" ] && out=$2; shift; done',
    ]
    for n, (code, text) in enumerate(outcomes, 1):
        cond = f"[ $c -ge {n} ]" if n == len(outcomes) else f"[ $c -eq {n} ]"
        if code == 0:
            lines.append(f"if {cond}; then printf '%s' '{text}' > \"$out\"; exit 0; fi")
        else:
            lines.append(f"if {cond}; then echo '{text}' >&2; exit {code}; fi")
    p = bindir / "gh"
    p.write_text("\n".join(lines) + "\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def _gh_runs(gh: Path) -> int:
    n = Path(f"{gh}.n")
    return int(n.read_text().strip()) if n.exists() else 0


def _run(tmp: Path, url: str, gh: bool) -> subprocess.CompletedProcess[str]:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    for tool in ("curl", "tr", "sed", "grep", "rm", "cat", "printf"):
        found = shutil.which(tool)
        if found and not (bindir / tool).exists():
            (bindir / tool).symlink_to(found)
    if not gh and (bindir / "gh").exists():
        (bindir / "gh").unlink()
    script = (
        _helpers()
        + "\nDL_ATTEMPTS=3\n"
        + 'sleep() { echo "$1" >> "$tmpdir/sleeps"; }\n'
        + f'tmpdir="{tmp}"\n'
        + f'if download "{url}" "{tmp}/out"; then echo OK; else echo "FAIL class=$DL_CLASS"; fi\n'
    )
    env = {"PATH": str(bindir), "HOME": str(tmp)}
    return subprocess.run(
        [shutil.which("sh") or "/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_a_404_is_asked_once_and_says_not_found(tmp_path: Path) -> None:
    srv = _Server([(404, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "FAIL class=notfound" in r.stdout, r
    assert srv.hits == 1, "a real 404 is never retried"
    assert "check the release tag" in r.stderr


def test_a_503_then_200_succeeds(tmp_path: Path) -> None:
    srv = _Server([(503, {}, b""), (200, {}, b"payload")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "OK" in r.stdout, r
    assert srv.hits == 2
    assert (tmp_path / "out").read_bytes() == b"payload"


def test_server_errors_retry_to_the_bound(tmp_path: Path) -> None:
    srv = _Server([(502, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "FAIL class=server" in r.stdout, r
    assert srv.hits == 3, "DL_ATTEMPTS tries in all"
    assert "githubstatus.com" in r.stderr


@pytest.mark.parametrize("status", [401, 403])
def test_auth_refused_is_asked_once(tmp_path: Path, status: int) -> None:
    srv = _Server([(status, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "FAIL class=auth" in r.stdout, r
    assert srv.hits == 1
    assert "gh auth login" in r.stderr


def test_a_403_with_an_exhausted_limit_is_rate_limited(tmp_path: Path) -> None:
    srv = _Server([(403, {"X-RateLimit-Remaining": "0"}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "FAIL class=rate" in r.stdout, r
    assert "for a higher limit" in r.stderr


def test_a_429_is_retried_then_served(tmp_path: Path) -> None:
    srv = _Server([(429, {"Retry-After": "1"}, b""), (200, {}, b"ok")])
    try:
        r = _run(tmp_path, srv.url(), gh=False)
    finally:
        srv.close()
    assert "OK" in r.stdout, r
    assert srv.hits == 2


def test_a_refused_connection_is_a_network_error(tmp_path: Path) -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    r = _run(tmp_path, f"http://127.0.0.1:{port}/o/r/releases/download/t/a", gh=False)
    assert "FAIL class=network" in r.stdout, r
    assert "check DNS, the proxy and connectivity" in r.stderr


def test_a_gh_network_failure_is_not_reported_as_a_404(tmp_path: Path) -> None:
    """The i11b incident: gh fails on the network, the plain GET to a private
    repo would 404. The report is gh's, after gh's retries, and curl is not
    asked to repeat GitHub's answer."""
    (tmp_path / "bin").mkdir()
    gh = _fake_gh(tmp_path / "bin", [(1, "error connecting to api.github.com")])
    srv = _Server([(404, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=True)
    finally:
        srv.close()
    assert "FAIL class=network" in r.stdout, r
    assert _gh_runs(gh) == 3, "gh's transient failure is retried to the bound"
    assert srv.hits == 0
    assert "HTTP 404" not in r.stderr
    assert (tmp_path / "sleeps").read_text().split() == ["1", "2"], "backoff doubles"


def test_gh_then_success_after_a_blip(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    gh = _fake_gh(tmp_path / "bin", [(1, "HTTP 502: Bad Gateway"), (0, "bytes")])
    r = _run(tmp_path, "https://github.com/o/r/releases/download/t/a", gh=True)
    assert "OK" in r.stdout, r
    assert _gh_runs(gh) == 2
    assert (tmp_path / "out").read_text() == "bytes"


def test_gh_not_found_is_final(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    gh = _fake_gh(tmp_path / "bin", [(1, "no assets match the file pattern")])
    srv = _Server([(200, {}, b"should not be fetched")])
    try:
        r = _run(tmp_path, srv.url(), gh=True)
    finally:
        srv.close()
    assert "FAIL class=notfound" in r.stdout, r
    assert _gh_runs(gh) == 1
    assert srv.hits == 0


def test_gh_not_logged_in_falls_back_to_the_public_lane(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    _fake_gh(
        tmp_path / "bin",
        [(4, "To get started with GitHub CLI, please run:  gh auth login")],
    )
    srv = _Server([(200, {}, b"public")])
    try:
        r = _run(tmp_path, srv.url(), gh=True)
    finally:
        srv.close()
    assert "OK" in r.stdout, r
    assert srv.hits == 1


def test_gh_not_logged_in_and_private_says_both(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    _fake_gh(
        tmp_path / "bin",
        [(4, "To get started with GitHub CLI, please run:  gh auth login")],
    )
    srv = _Server([(404, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=True)
    finally:
        srv.close()
    assert "FAIL" in r.stdout, r
    assert "gh failed first" in r.stderr and "gh auth login" in r.stderr


def test_tokens_are_redacted(tmp_path: Path) -> None:
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0"
    (tmp_path / "bin").mkdir()
    _fake_gh(tmp_path / "bin", [(1, f"HTTP 401: Bad credentials {tok}")])
    srv = _Server([(404, {}, b"")])
    try:
        r = _run(tmp_path, srv.url(), gh=True)
    finally:
        srv.close()
    assert tok not in r.stderr and tok not in r.stdout
    assert "[redacted]" in r.stderr


def test_a_manifest_fetch_failure_is_not_called_unsigned() -> None:
    """The refusal stays, but a manifest that could not be FETCHED is said as
    that, before the "publishes no signed manifest" branch can claim it."""
    text = INSTALL.read_text()
    fetch_fail = text.index("could not fetch the signed manifest")
    unsigned = text.index('err "no signed release manifest at')
    assert fetch_fail < unsigned
    assert '[ "$DL_CLASS" != notfound ]' in text[:fetch_fail]


def test_tls_is_never_relaxed() -> None:
    text = INSTALL.read_text()
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    for bad in (" -k ", "--insecure", "--no-check-certificate"):
        assert bad not in code, bad


if os.name != "posix":  # pragma: no cover
    pytest.skip("POSIX shell only", allow_module_level=True)
