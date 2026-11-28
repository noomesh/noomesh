# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every pro file a Rust build.rs cfg-gates must be absent from this public tree.

The `has_*` cfg pattern in a build.rs exists for one reason: the file is
PRO-ONLY (today: noo-cli's licence signer, `src/commands/entitlement_signer.rs`,
built privately), so the public tree must compile without it. The public repo
is where work lands directly, so the guard is not an exclusion list in a sync
script but the plainest fact: **no cfg-gated pro path is tracked here.** A
commit that adds one fails this test, and `.gitignore` keeps a local copy (a
private build drops the file in) out of `git add`.

The requirement is DERIVED from build.rs rather than restated here, so a new
pro file gets covered by adding its cfg gate to build.rs.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Every build.rs whose job is detecting optional pro sources.
BUILD_SCRIPTS = ("gateway-rust/build.rs", "noo-cli/build.rs")


def _guarded_paths(build_rs: Path) -> list[str]:
    """Literal paths a build.rs watches, repo-relative.

    These scripts watch pro files by literal path; noo-cli/build.rs also emits
    `rerun-if-changed={}` per embedded repo asset through a FORMAT STRING, a
    placeholder that carries no pro meaning and is filtered out here.
    """
    text = build_rs.read_text()
    rel = re.findall(r"rerun-if-changed=([^\"\s]+)", text)
    rel = [p for p in rel if "{" not in p]
    return [f"{build_rs.parent.name}/{p}" for p in rel]


def _tracked(path: str) -> bool:
    """Whether git tracks `path` in this checkout (an untracked local copy is not a commit)."""
    r = subprocess.run(["git", "-C", str(REPO), "ls-files", "--error-unmatch", "--", path],
                       capture_output=True, text=True)
    return r.returncode == 0


# The pro paths a build.rs watches but that are also ordinary repo sources
# (watched for a non-pro reason). Each needs a reason; none today besides the
# add-on declaration parser noo-cli/build.rs includes as a module.
NOT_PRO = {
    "noo-cli/src/addon_decl_parse.rs": "build.rs includes it as a module (add-on declarations), not a pro source",
}


@pytest.mark.parametrize("script", BUILD_SCRIPTS)
def test_cfg_gated_pro_files_are_not_tracked_in_the_public_tree(script: str) -> None:
    build_rs = REPO / script
    assert build_rs.exists(), f"{script} is part of this tree"
    watched = [p for p in _guarded_paths(build_rs) if p not in NOT_PRO]
    if not watched:
        # Every cfg-gated pro source of this build.rs is retired (gateway-rust
        # since 2026-08-23). A literal rerun-if-changed the regex failed to
        # parse would show up here instead.
        stray = re.findall(r"rerun-if-changed=(?!\{)", build_rs.read_text())
        parsed = len(_guarded_paths(build_rs))
        assert len(stray) == parsed, f"{script}: {len(stray) - parsed} literal watch(es) the extraction did not parse"
        return
    tracked = [p for p in watched if _tracked(p)]
    assert not tracked, (
        f"{script} cfg-gates {tracked} as pro-only, and they are tracked in this public tree: "
        "remove them from the commit (they are built privately); .gitignore lists them"
    )


def test_every_cfg_gated_pro_file_is_gitignored() -> None:
    """A private build drops the pro file into a checkout; .gitignore keeps `git add -A` from taking it."""
    ignore = (REPO / ".gitignore").read_text().splitlines()
    for script in BUILD_SCRIPTS:
        for p in _guarded_paths(REPO / script):
            if p in NOT_PRO:
                continue
            assert p in ignore or f"/{p}" in ignore, f"{p} (cfg-gated by {script}) is not in .gitignore"


def test_the_guard_sees_a_tracked_pro_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard itself is real: pointed at a repo that tracks a cfg-gated path, `_tracked` finds
    it (and `_guarded_paths` reads the path out of the build script); an untracked copy is not found."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    crate = tmp_path / "fake-crate"
    crate.mkdir()
    (crate / "build.rs").write_text('fn main() { println!("cargo:rerun-if-changed=src/pro.rs"); }\n')
    (crate / "src").mkdir()
    (crate / "src" / "pro.rs").write_text("// pro\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "fake-crate/build.rs"], check=True)
    monkeypatch.setattr(sys.modules[__name__], "REPO", tmp_path)
    assert _guarded_paths(crate / "build.rs") == ["fake-crate/src/pro.rs"]
    assert not _tracked("fake-crate/src/pro.rs"), "an untracked local copy is not a commit"
    subprocess.run(["git", "-C", str(tmp_path), "add", "fake-crate/src/pro.rs"], check=True)
    assert _tracked("fake-crate/src/pro.rs"), "a tracked cfg-gated path is found"


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
