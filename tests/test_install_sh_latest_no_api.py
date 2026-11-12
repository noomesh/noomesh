# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""install.sh resolves "latest" without the GitHub API (2026-11-12).

The install matrix's macOS cell failed at the README's first line: install.sh
asked the anonymous API for the release list and got 403, because the API
allows 60 requests an hour per IP and a hosted runner, like an office or a
carrier NAT, shares its IP. Now the default path reads the redirect of
github.com/<repo>/releases/latest, which names the noo-cli final by
construction. The API is used only for a prerelease, or when the redirect
names no noo-cli tag.

These drive the REAL resolution block of the shipped script with a fake
`curl`/`gh` on PATH that log every URL and answer like GitHub does: the
transport is faked, not the function.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "noo-cli" / "install.sh"


def _resolution_block() -> str:
    """install.sh from its helpers through the version resolution, stopping
    before anything is downloaded."""
    text = INSTALL.read_text()
    head = text[:text.index("err() {")]
    keep = "\n".join(l for l in head.splitlines() if l.startswith(("REPO=", "GITHUB_API=", "GITHUB_DL=", "GITHUB_LATEST=")))
    helpers = text[text.index("err() {"):text.index('# Compute the SHA-256 of file "$1"')]
    start = text.index('if [ -n "${NOO_CLI_BASE_URL:-}" ]; then')
    end = text.index('info "Release: ${version}"')
    return keep + "\nDL_ATTEMPTS=2\n" + helpers + "\n" + text[start:end] + '\necho "VERSION=$version"\n'


API_JSON = ('[{"tag_name":"stack-v9.0.0","draft":false,"prerelease":false},'
            '{"tag_name":"noo-cli-v9.1.0-rc.1","draft":false,"prerelease":true},'
            '{"tag_name":"noo-cli-v9.0.0","draft":false,"prerelease":false}]')


def _run(tmp: Path, *, redirect: str, env_extra: dict | None = None, with_gh: bool = False):
    bindir = tmp / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    log = tmp / "urls.log"
    (bindir / "curl").write_text(f"""#!/bin/sh
for a; do case "$a" in http*) echo "curl $a" >> "{log}"; url="$a";; esac; done
case "$url" in
  */releases/latest) printf '%s' '{redirect}' ;;
  https://api.github.com/*) printf '%s' '{API_JSON}' ;;
  *) exit 22 ;;
esac
""")
    if with_gh:
        (bindir / "gh").write_text(f"""#!/bin/sh
echo "gh $*" >> "{log}"
printf '%s' '{API_JSON}'
""")
    for f in bindir.iterdir():
        f.chmod(0o755)
    for tool in ("tr", "sed", "awk", "tail", "cat", "printf", "mktemp", "rm", "uname"):
        found = shutil.which(tool)
        if found and not (bindir / tool).exists():
            (bindir / tool).symlink_to(found)
    env = {"PATH": str(bindir), "HOME": str(tmp), **(env_extra or {})}
    r = subprocess.run([shutil.which("sh") or "/bin/sh", "-c", _resolution_block()], capture_output=True, text=True,
                       env=env, timeout=60)
    urls = log.read_text().splitlines() if log.exists() else []
    return r, urls


def test_the_default_path_makes_no_api_request(tmp_path):
    r, urls = _run(tmp_path, redirect="https://github.com/noomesh/noomesh/releases/tag/noo-cli-v9.0.0", with_gh=True)
    assert "VERSION=noo-cli-v9.0.0" in r.stdout, r.stdout + r.stderr
    assert urls == ["curl https://github.com/noomesh/noomesh/releases/latest"], urls
    assert not any("api.github.com" in u or u.startswith("gh ") for u in urls), \
        "a stranger behind shared NAT must not need the rate-limited API"


def test_a_prerelease_still_reads_the_listing(tmp_path):
    r, urls = _run(tmp_path, redirect="https://github.com/noomesh/noomesh/releases/tag/noo-cli-v9.0.0",
                   env_extra={"NOO_CLI_PRERELEASE": "1"})
    assert "VERSION=noo-cli-v9.1.0-rc.1" in r.stdout, r.stdout + r.stderr
    assert urls and all("releases/latest" not in u for u in urls), "\"latest\" is never a prerelease: not asked"
    assert any("api.github.com" in u for u in urls)


def test_a_redirect_that_names_no_cli_tag_falls_back_to_the_listing(tmp_path):
    # e.g. a stack release wrongly marked Latest: the redirect is not trusted
    # for a tag that is not noo-cli-v*.
    for redirect in ("https://github.com/noomesh/noomesh/releases/tag/stack-v9.0.0", ""):
        r, urls = _run(tmp_path / (redirect[-5:] or "empty"), redirect=redirect)
        assert "VERSION=noo-cli-v9.0.0" in r.stdout, (redirect, r.stdout, r.stderr)
        assert any("api.github.com" in u for u in urls)


def test_a_pinned_version_asks_nobody(tmp_path):
    r, urls = _run(tmp_path, redirect="unused", env_extra={"NOO_CLI_VERSION": "0.6.23"})
    assert "VERSION=noo-cli-v0.6.23" in r.stdout and urls == [], (r.stdout, urls)
