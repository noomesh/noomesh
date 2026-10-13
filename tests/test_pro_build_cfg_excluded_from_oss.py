# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every pro file a Rust build.rs cfg-gates must be stripped by the OSS sync.

The `has_pro_*` cfg pattern exists for exactly one reason: the file is
PRO-ONLY and gets removed on the way to the public repo, so the OSS tree has
to compile without it. A file that is cfg-gated but NOT in PRO_EXCLUDES is
therefore always a bug, and specifically a licence leak — the gating says
"this is pro" while the sync ships it anyway.

That is not hypothetical. `gateway-rust/migrations/0002_pro.sql` (the pro half
of the mesh schema baseline) was added
with its cfg gate but without its exclusion, and nothing caught it, because
until this file there was no test over PRO_EXCLUDES at all.

The requirement is DERIVED from build.rs rather than restated here, so a new
pro file gets covered by adding it to build.rs — no one has to remember this
test exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SYNC = REPO / "scripts" / "sync-to-oss.sh"

# Every build.rs whose job is detecting optional pro sources.
BUILD_SCRIPTS = ("gateway-rust/build.rs", "noo-cli/build.rs")


def _guarded_paths(build_rs: Path) -> list[str]:
    """Paths a build.rs watches, repo-relative.

    These scripts exist solely to detect pro files, so every watched path is a
    pro path. If that ever stops being true, this assertion is the right place
    to find out — a non-pro watched path should be given an explicit allow-list
    here with a reason, not silently tolerated.
    """
    text = build_rs.read_text()
    rel = re.findall(r"rerun-if-changed=([^\"\s]+)", text)
    # Allow-listed non-pro watch (see docstring): noo-cli/build.rs also embeds
    # the standalone deploy slice and emits rerun-if-changed per asset
    # via a FORMAT STRING — the source literal is `rerun-if-changed={}`, a
    # placeholder, not a path. The watched files are repo assets (compose,
    # prompts, monitoring…), not pro sources; only literal-path watches carry
    # this test's pro meaning.
    rel = [p for p in rel if "{" not in p]
    return [f"{build_rs.parent.name}/{p}" for p in rel]


def _pro_excludes() -> str:
    return SYNC.read_text()


@pytest.mark.parametrize("script", BUILD_SCRIPTS)
def test_cfg_gated_pro_files_are_excluded_from_the_oss_sync(script: str) -> None:
    build_rs = REPO / script
    if not build_rs.exists():
        pytest.skip(f"{script} not present")

    watched = _guarded_paths(build_rs)
    if not watched:
        # An empty watch list is legitimate once every cfg-gated pro source
        # is retired — the strongest exclusion is nonexistence (see the
        # sibling test). gateway-rust reached this state on 2026-08-23:
        # routes/pro.rs retired in the design and 0002_pro.sql deleted
        # in phase B'. The broken-detection case the old bare assert guarded
        # is the OTHER shape: the script still emits rerun-if-changed lines
        # but the regex extracted none of them.
        # noo-cli reached the same state on 2026-10-05: hloop.rs retired in
        # #759 (add-ons bring their own `noo` commands), so its only watches
        # left are the `{}` placeholders _guarded_paths filters on purpose.
        # Broken-regex detection therefore asks the precise question: is any
        # rerun-if-changed NOT a placeholder? A literal path the regex failed
        # to extract would show up here.
        stray = re.findall(r"rerun-if-changed=(?!\{)", build_rs.read_text())
        assert not stray, (
            f"{script} emits {len(stray)} literal rerun-if-changed line(s) the "
            "extraction did not parse — the cfg detection regex is broken"
        )
        return

    sync = _pro_excludes()
    missing = [p for p in watched if f'"{p}"' not in sync]
    assert not missing, (
        f"{script} cfg-gates {missing} as pro-only, but scripts/sync-to-oss.sh "
        "does not exclude them. The gate means the OSS tree must compile "
        "WITHOUT the file, so shipping it is both a licence leak and a lie "
        "about the build. Add each path to PRO_EXCLUDES."
    )


def test_the_mesh_pro_baseline_stays_deleted() -> None:
    """The strongest exclusion is nonexistence.

    This test used to assert 0002_pro.sql was in PRO_EXCLUDES — named
    explicitly so deleting the cfg gate could not quietly delete the
    coverage. That guard fired exactly as designed when phase B' deleted the
    file and its gate together, which is the one legitimate way for both to
    go: evolve's five tables now come from evolve's OWN chain, in its own
    repo, so there is no pro DDL here to strip OR to leak.

    The assertion flips accordingly: the file must stay gone. If it ever
    reappears, either the split regressed or someone is reintroducing
    another system's DDL into mesh — both worth a loud stop.
    """
    assert not (REPO / "gateway-rust/migrations/0002_pro.sql").exists(), (
        "0002_pro.sql is back — mesh must not ship evolve's tables "
        "; evolve's chain owns them"
    )
    assert not (REPO / "gateway-rust/migrations/0003_cross_domain_pro.sql").exists(), (
        "0003 is back — mesh must not create cross-domain objects (phase C)"
    )
