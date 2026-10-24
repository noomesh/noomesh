# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""install.sh resolves the newest FINAL noo-cli release, not a candidate.

0.6.11-rc.1: the one-line install (`curl -fsSL .../releases/latest/download/
install.sh | sh`) took the newest `noo-cli-v*` tag from the releases listing,
and a release candidate is the newest release object while it is out, so a
stranger installing during an rc window got the rc. `noo upgrade` already
skipped prereleases; the installer now does too, through pick_cli_tag(),
which both the gh lane and the public-API lane pipe through. These tests run
the real function from the shipped script on listings shaped like GitHub's,
compact and pretty.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "noo-cli" / "install.sh"


def _function() -> str:
    text = INSTALL.read_text()
    i = text.index("pick_cli_tag() {")
    j = text.index("\nfetch() {")
    return text[i:j]


def _rel(tag: str, *, pre: bool = False, draft: bool = False) -> dict:
    # The key order GitHub returns, with nested objects that must not confuse
    # the parse (author before tag_name, assets after prerelease).
    return {
        "url": f"https://api.github.com/repos/o/r/releases/{tag}",
        "author": {"login": "bot", "id": 1, "type": "Bot", "site_admin": False},
        "node_id": "RE_x",
        "tag_name": tag,
        "target_commitish": "main",
        "name": tag,
        "draft": draft,
        "immutable": False,
        "prerelease": pre,
        "created_at": "2026-10-24T19:00:00Z",
        "assets": [{"name": "noo-x86_64", "uploader": {"login": "bot", "site_admin": False}, "state": "uploaded"}],
        "body": "notes, with commas, and \"quotes\"",
    }


def pick(listing: list[dict], *, pretty: bool, prerelease: str | None = None) -> str:
    body = json.dumps(listing, indent=2 if pretty else None, separators=None if pretty else (",", ":"))
    env = {k: v for k, v in os.environ.items() if k != "NOO_CLI_PRERELEASE"}
    if prerelease is not None:
        env["NOO_CLI_PRERELEASE"] = prerelease
    p = subprocess.run(["sh", "-c", _function() + "\npick_cli_tag"], input=body, env=env,
                       capture_output=True, text=True, check=True)
    return p.stdout.strip()


RC_WINDOW = [
    _rel("stack-v0.6.11-rc.1", pre=True),
    _rel("noo-cli-v0.6.11-rc.1", pre=True),
    _rel("stack-v0.6.10"),
    _rel("noo-cli-v0.6.10"),
    _rel("noo-cli-v0.6.10-rc.7", pre=True),
]


@pytest.mark.parametrize("pretty", [True, False])
def test_an_rc_window_installs_the_last_final(pretty: bool) -> None:
    assert pick(RC_WINDOW, pretty=pretty) == "noo-cli-v0.6.10"


@pytest.mark.parametrize("pretty", [True, False])
def test_the_opt_in_takes_the_candidate(pretty: bool) -> None:
    assert pick(RC_WINDOW, pretty=pretty, prerelease="1") == "noo-cli-v0.6.11-rc.1"


@pytest.mark.parametrize("pretty", [True, False])
def test_a_draft_is_never_picked(pretty: bool) -> None:
    listing = [_rel("noo-cli-v0.7.0", draft=True), _rel("noo-cli-v0.6.11")]
    assert pick(listing, pretty=pretty) == "noo-cli-v0.6.11"
    assert pick(listing, pretty=pretty, prerelease="1") == "noo-cli-v0.6.11"


def test_other_components_are_skipped() -> None:
    assert pick([_rel("stack-v0.6.11"), _rel("noo-cli-v0.6.11")], pretty=True) == "noo-cli-v0.6.11"


def test_no_final_resolves_nothing() -> None:
    # The caller then errs with the pin hint; it never falls back to an rc.
    assert pick([_rel("noo-cli-v0.6.11-rc.1", pre=True)], pretty=False) == ""


def test_both_lanes_go_through_the_picker() -> None:
    text = INSTALL.read_text()
    block = text[text.index('info "Resolving latest noo-cli release..."'):text.index('bin_url="${GITHUB_DL}')]
    assert block.count("| pick_cli_tag") == 2, block
    assert "--jq '.[].tag_name'" not in block
