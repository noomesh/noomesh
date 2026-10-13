# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every shell script the Rust CLI references must ride the standalone binary.

Finding #28's class, rediscovered 2026-09-01 on the host8 standalone
controller: nine verb-invoked scripts (`stack stop/status/clean/logs/reset/
rebuild/sandbox`, `models convert`, `security secrets absorb-files`) were
missing from build.rs's STANDALONE asset list. Dev clones masked the gap for
months because pre-v0.3.7 root resolution preferred the cwd checkout, where
scripts/ always exists; the state-home-first ranking made the embedded set
authoritative — and incomplete.

The `embedded_launchers_have_their_libs` Rust test pins launcher-SOURCED libs;
this one pins the wider set: any `*.sh` literal in noo-cli/src that names a
real file under scripts/ must appear in build.rs. Mentions in error messages
count on purpose — a hint telling the operator to run a script the install
does not ship is itself a defect.
"""

import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_cli_referenced_scripts_are_embedded():
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    embedded = set(re.findall(r"scripts/([A-Za-z0-9._-]+)", build))

    referenced = set()
    for rs in (ROOT / "noo-cli" / "src").rglob("*.rs"):
        for name in re.findall(r'"(?:scripts/)?([a-z0-9-]+\.sh)"', rs.read_text()):
            if (ROOT / "scripts" / name).is_file():
                referenced.add(name)

    missing = sorted(referenced - embedded)
    assert not missing, (
        f"scripts referenced by noo-cli but absent from build.rs STANDALONE "
        f"assets (standalone installs cannot run them): {missing}"
    )


def _embedded_scripts() -> set[str]:
    """Scripts build.rs actually embeds: the quoted STANDALONE entries.

    Quoted on purpose. A bare mention in a build.rs comment (it cites
    scripts/sync-to-oss.sh to explain the exclude pattern) is not an
    embedding, and counting it made this test demand that the OSS sync's
    private libs ship on a standalone controller.
    """
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    return set(re.findall(r'"scripts/([A-Za-z0-9._-]+\.sh)"', build))


def _sourced_libs(body: str) -> dict[str, int]:
    """{lib filename: 1-based line of the source/dot line}."""
    found: dict[str, int] = {}
    for n, line in enumerate(body.splitlines(), 1):
        t = line.strip()
        if t.startswith("#") or not (t.startswith("source ") or t.startswith(". ")):
            continue
        m = re.search(r"(lib-[a-z0-9-]+\.sh)", t)
        if m:
            found.setdefault(m.group(1), n)
    return found


def test_libs_sourced_by_embedded_launchers_are_themselves_embedded():
    """A lib a shipped launcher sources must ship too.

    The Rust `embedded_launchers_have_their_libs` test checks the same class
    but is inert in CI: the noo-cli job builds the crate OUTSIDE the repo
    tree, so STANDALONE_ASSETS is empty and the test returns early. That
    hole let scripts/lib-ui.sh ship in nine `source` lines and zero installs
    (host8, 2026-09-03). This test reads the repo, so it always runs.
    """
    embedded = _embedded_scripts()
    missing = []
    for name in sorted(embedded):
        f = ROOT / "scripts" / name
        if not f.is_file():
            continue
        for lib in _sourced_libs(f.read_text()):
            if lib not in embedded:
                missing.append(f"{name} sources {lib}")
    assert not missing, (
        "embedded launchers source libs that are NOT in build.rs "
        f"STANDALONE_FILES — standalone installs die at that line: {missing}"
    )


def test_launchers_source_their_ui_helpers_before_calling_them():
    """`set -e` turns an undefined helper into exit 127.

    noomesh-start.sh called ui_kv in the digest-pin block at line 315 and
    sourced lib-ui.sh at line 393, so every `--dist` start with a stack.lock
    present exited 127 (host8, 2026-09-03, `noo upgrade --all`). Ordering,
    not presence, so the embedding test above cannot see it. lib-*.sh files
    are exempt: they call ui_* behind a `declare -F` guard because scripts
    that print nothing styled source them too.
    """
    bad = []
    for f in sorted((ROOT / "scripts").glob("*.sh")):
        if f.name.startswith("lib-"):
            continue
        body = f.read_text()
        uses = [
            n for n, line in enumerate(body.splitlines(), 1)
            if re.search(r"(^|[^\w.])ui_[a-z_]+ ", line) and not line.strip().startswith("#")
        ]
        if not uses:
            continue
        src = _sourced_libs(body).get("lib-ui.sh")
        if src is None:
            bad.append(f"{f.name} calls ui_* (line {uses[0]}) but never sources lib-ui.sh")
        elif uses[0] < src:
            bad.append(f"{f.name} calls ui_* at line {uses[0]}, sources lib-ui.sh at {src}")
    assert not bad, "launchers use ui helpers before defining them: " + "; ".join(bad)


def test_repo_files_the_cli_reads_at_runtime_are_embedded():
    """Every `root.join("…")` file the CLI reads must ride the binary.

    The scripts test above covers `scripts/*.sh`. This one covers the rest
    of the class, and it exists because the rest of the class bit: the
    harness pair (`node-agent-go/deploy/noo-harness.env.tmpl` and
    `.service`) was read by `cluster provision`
    through `repo_root()` and never added to build.rs. Its NEIGHBOUR in the
    very same directory — `noo-node-agent.env.tmpl` — was listed, which is
    what made the gap invisible: a well-guarded neighbour is evidence about
    the neighbour, never about the file beside it.

    The live cost, host8 2026-09-19: `noo upgrade --nodes` failed on all
    four non-controller nodes with "Cannot read the harness env template
    (No such file or directory)". The controller's own node passed, because
    it skips the harness block — so the one node an operator watches most
    closely was the one node that could not fail.

    A standalone install IS `~/.noo`: `repo_root()` ranks the state home
    above a checkout, and only embedded assets are materialised there. So
    "it works in my clone" proves nothing about the shipped binary.
    """
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    # Directories embedded wholesale (STANDALONE_DIRS) cover everything under them.
    dirs = re.search(r"STANDALONE_DIRS:\s*&\[&str\]\s*=\s*&\[([^\]]*)\]", build, re.S)
    embedded_dirs = tuple(re.findall(r'"([^"]+)"', dirs.group(1))) if dirs else ()
    tracked = set(subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split())

    referenced: set[str] = set()
    for rs in (ROOT / "noo-cli" / "src").rglob("*.rs"):
        for line in rs.read_text().splitlines():
            for rel in re.findall(r'root\.join\("([^"]+)"\)', line):
                # A path the CLI PROBES is a marker (does this tree look like
                # a checkout / a standalone home); a path it READS is an asset
                # the install must carry. `pyproject.toml` is the former.
                if re.search(r'root\.join\("' + re.escape(rel) + r'"\)\s*\.\s*(exists|is_file|is_dir)\(', line):
                    continue
                # Tracked files only: `pki/`, `secrets/`, `.env` and `stack.lock`
                # are live state a box writes, not source that ships.
                if rel in tracked:
                    referenced.add(rel)

    missing = sorted(
        rel for rel in referenced
        if f'"{rel}"' not in build and not rel.startswith(embedded_dirs)
    )
    assert not missing, (
        "repo files the CLI reads through repo_root() but build.rs does not "
        f"embed — a standalone install (~/.noo) has no copy: {missing}"
    )
