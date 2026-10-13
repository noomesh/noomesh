# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The release repo is declared ONCE. Every caller resolves it.

`NOO_CLI_REPO` is the distribution-channel knob: the internal private
repo is the default, and the public channel is meant to be a config flip rather
than a code change. That only holds if every caller asks.

Five did not. They had the old repo name typed out, so setting
NOO_CLI_REPO moved SOME traffic and silently left the rest pointing at the old
repo — including `provision.rs`'s darwin agent download, the lane that had
already shipped a three-month-stale agent to a Mac because nothing compared what
it fetched against what was asked for.

A half-moved release location is worse than an unmoved one: both halves report
success, and the failure is a node quietly installing from a repo nobody is
publishing to any more.

This is the same guard shape as test_node_tier_ladder_parity and
test_nats_node_subject_parity — no compiler spans "a literal string" and "the
function that should have produced it", so the check is textual.
"""

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[1] / "noo-cli" / "src"
LITERAL = "noomesh/noomesh"

# The ONE place the default may be written, and the installer, which is a
# standalone shell script with no access to the Rust resolver (it has its own
# NOO_CLI_REPO override, checked separately below).
ALLOWED = {"registry.rs"}


def _rust_sources():
    return sorted(p for p in SRC.rglob("*.rs"))


def test_the_repo_literal_appears_only_where_the_default_is_declared():
    offenders = []
    for path in _rust_sources():
        rel = path.relative_to(SRC).as_posix()
        if rel in ALLOWED:
            continue
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if LITERAL in line and not line.lstrip().startswith("//"):
                offenders.append(f"{rel}:{i}")
    assert not offenders, (
        "the release repo is typed out instead of resolved — these ignore "
        f"NOO_CLI_REPO and would keep using the old repo after a move: {offenders}"
    )


def test_the_declaration_site_still_declares_it():
    """Guard the guard: if the default moves or is renamed, the allowlist above
    silently starts permitting nothing, and an empty search passes vacuously."""
    reg = (SRC / "registry.rs").read_text()
    assert re.search(r'RELEASE_REPO:\s*&str\s*=\s*"' + re.escape(LITERAL) + r'"', reg), (
        "registry.rs no longer declares RELEASE_REPO with the expected literal — "
        "this test's allowlist is now guarding an empty set"
    )
    text = (SRC / "commands" / "upgrade.rs").read_text()
    assert re.search(r"DEFAULT_REPO:\s*&str\s*=\s*crate::registry::RELEASE_REPO;", text), (
        "upgrade.rs DEFAULT_REPO no longer reads the declared RELEASE_REPO"
    )
    assert "pub(crate) fn repo()" in text, (
        "the shared resolver is gone or no longer crate-visible; callers will "
        "reintroduce the literal"
    )


def test_the_non_rust_homes_agree_with_the_declared_one():
    """install.sh, install-noo.sh (curl|sh, cannot import) and the gateway
    (separate crate) carry their own default; all must equal RELEASE_REPO."""
    root = SRC.parents[1]
    want = re.search(r'RELEASE_REPO:\s*&str\s*=\s*"([^"]+)"', (SRC / "registry.rs").read_text()).group(1)
    for rel, rx in [
        ("noo-cli/install.sh", r'REPO="\$\{NOO_CLI_REPO:-([^}]+)\}"'),
        ("scripts/install-noo.sh", r'REPO="\$\{NOO_CLI_REPO:-([^}]+)\}"'),
        ("gateway-rust/src/routes/bootstrap.rs", r'DEFAULT_CLI_REPO:\s*&str\s*=\s*"([^"]+)"'),
    ]:
        m = re.search(rx, (root / rel).read_text())
        assert m, f"{rel}: release-repo default not found — update this test"
        assert m.group(1) == want, f"{rel} defaults to {m.group(1)!r}, declared is {want!r}"


def test_the_installer_keeps_its_own_override():
    """install.sh is a standalone script and cannot call the Rust resolver, so
    it carries the same knob. It must keep it: the installer is how a node gets
    its FIRST binary, and a wrong repo there strands enrollment entirely."""
    sh = (SRC.parent / "install.sh").read_text()
    assert 'REPO="${NOO_CLI_REPO:-' in sh, (
        "install.sh no longer honours NOO_CLI_REPO"
    )
