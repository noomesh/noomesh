# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Per-image re-tag: an rc re-cut rebuilds only the images whose build inputs
changed (see #305 for the same-tree re-tag this extends).

Two halves:

  * the stale-table guard — scripts/release-image-inputs.json is the ONE place
    an image's inputs are declared; if a Dockerfile starts COPYing a path the
    table does not list, an rc that changes only that path would re-tag a stale
    image. These tests fail first;
  * the plan — a diff between two rcs turns into a per-image build/re-tag
    decision, failing safe (to BUILD) on anything it cannot prove.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("release_retag_plan", ROOT / "scripts/release-retag-plan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = _load()
TABLE = P.load_inputs()
IMAGES = TABLE["images"]
WF = yaml.safe_load((ROOT / ".github/workflows/images-release.yml").read_text())
MATRIX = WF["jobs"]["images"]["strategy"]["matrix"]["include"]


# --------------------------------------------------------------- the guard

def test_every_dockerfile_copy_is_a_declared_input():
    """THE guard: no COPY/ADD source (from the build context) outside the
    image's declared inputs."""
    for img, spec in IMAGES.items():
        text = (ROOT / spec["dockerfile"]).read_text()
        bad = P.uncovered_sources(text, spec["context"], spec["inputs"])
        assert not bad, (f"{spec['dockerfile']} ({img}) COPYs {bad} which scripts/release-image-inputs.json "
                         f"does not list under images.{img}.inputs — an rc that changes only that path "
                         "would re-tag a stale image. Add it.")


def test_the_guard_catches_an_undeclared_copy_path():
    fixture = "FROM scratch\nCOPY src ./src\nCOPY --chmod=755 extra/tool.sh /bin/\nCOPY --from=builder /x /y\n"
    assert P.uncovered_sources(fixture, ".", ["src/**"]) == ["extra/tool.sh"]
    assert P.uncovered_sources(fixture, ".", ["src/**", "extra/**"]) == []


def test_the_guard_resolves_paths_against_the_build_context():
    # context ./docker: `COPY tool.py` is docker/tool.py
    assert P.uncovered_sources("COPY tool.py /t\n", "./docker", ["docker/other.py"]) == ["docker/tool.py"]
    assert P.uncovered_sources("COPY tool.py /t\n", "./docker", ["docker/tool.py"]) == []


def test_the_guard_fails_on_sources_it_cannot_resolve():
    for line in ("COPY ${SRC} /x", "ADD https://example.com/a.tgz /x", "COPY <<EOF /x\nhi\nEOF"):
        assert P.uncovered_sources(line + "\n", ".", ["**"]), line


def test_the_guard_reads_continuations_and_ignores_comments_and_stage_copies():
    fixture = "# COPY nope /x\nCOPY a \\\n  b \\\n  /dst/\nCOPY --from=trellion . /t\n"
    assert P.uncovered_sources(fixture, ".", ["a"]) == ["b"]


def test_a_directory_source_needs_a_glob_that_reaches_inside_it():
    assert P.uncovered_sources("COPY src ./src\n", ".", ["src/**"]) == []
    assert P.uncovered_sources("COPY src ./src\n", ".", ["src/only_this.py"]) == ["src"]


def test_the_table_names_exactly_the_images_the_plan_knows():
    assert set(IMAGES) == set(P.SIBLING_INPUTS)


def test_every_dockerfile_in_the_tree_is_declared_or_marked_unreleased():
    declared = {spec["dockerfile"] for spec in IMAGES.values()} | set(TABLE["unreleased_dockerfiles"])
    on_disk = {str(p.relative_to(ROOT)) for p in (ROOT / "docker").glob("Dockerfile.*")}
    assert on_disk == declared, f"undeclared: {sorted(on_disk - declared)}; stale: {sorted(declared - on_disk)}"


def test_the_table_agrees_with_the_workflow_matrix():
    for m in MATRIX:
        spec = IMAGES[m["image"]]
        assert spec["dockerfile"] == m["dockerfile"], m["image"]
        assert Path(spec["context"]) == Path(m["context"]), m["image"]
    for job, img in (("deps-core", "deps-core"), ("deps-base", "deps-base")):
        assert IMAGES[img]["dockerfile"] in str(WF["jobs"][job]), img


def test_parents_match_the_FROM_images_and_every_input_matches_a_tracked_file():
    for img, spec in IMAGES.items():
        text = (ROOT / spec["dockerfile"]).read_text()
        for parent, arg in (("deps-core", "DEPS_CORE"), ("deps-base", "DEPS_BASE")):
            assert (f"${{{arg}}}" in text) == (parent in spec["parents"]), f"{img}: parent {parent} vs FROM ${arg}"
    try:
        tracked = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True,
                                 check=True).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    for img, spec in IMAGES.items():
        for g in spec["inputs"] + (TABLE["lane"] if img == "deps-core" else []):
            assert any(P.covers([g], f) for f in tracked), f"{img}: input {g} matches no tracked file (stale?)"


# ---------------------------------------------------------------- the plan

LOCK = "".join(f"{i}@sha256:{i[:3]}\n" for i in
               ("gateway", "llamacpp", "node-agent", "nvidia-exporter", "piper", "postgres-pgvector",
                "sandbox", "stunnel", "trellion", "whisper", "worker")) + "source:trellion@TRE\n"
BASES = "deps-core@sha256:dc\ndeps-base@sha256:db\n"
RC1, RC2, NEW = "stack-v1.2.3-rc.1", "stack-v1.2.3-rc.2", "stack-v1.2.3-rc.3"


def _plan(changed, tag=NEW, rcs=(RC2, RC1), bases=BASES, lock=LOCK, table=None, trees=None):
    trees = trees or {NEW: "T3", RC2: "T2", RC1: "T1", "stack-v1.2.3": "T2"}
    return P.plan(tag, "o/r", {"trellion": "TRE"}, "t", "t", lock_text=lock, bases_text=bases,
                  tree_of=lambda ref: trees[ref], commit_of=lambda ref: "C-" + ref,
                  list_rcs=lambda final: list(rcs), sib_tree=lambda repo, sha, tok: "T-tre",
                  changed_of=lambda prev, new: changed, inputs_table=table)


def _built(p):
    return {i for i, r in p["retag"].items() if not r}


ALWAYS = {"gateway", "node-agent"}   # tag-stamped: never re-tagged


def test_a_lockfile_only_change_rebuilds_only_the_rust_image():
    """0.6.10 rc.7 = rc.6 + gateway-rust/Cargo.lock."""
    p = _plan(["gateway-rust/Cargo.lock", "noo-cli/Cargo.lock"])
    assert p["rc_tag"] == RC2
    assert _built(p) == ALWAYS, p["why"]
    assert p["why"]["worker"].startswith("re-tag from " + RC2), p["why"]
    assert p["rc_digests"]["deps-core"] == "sha256:dc" and p["rc_digests"]["whisper"] == "sha256:whi"


def test_a_ui_change_rebuilds_only_what_embeds_the_console():
    # the console image itself is built by publish-web.yml, not this lane; the
    # only stack image that embeds it is the gateway
    p = _plan(["ui/apps/web/src/App.tsx"])
    assert _built(p) == ALWAYS, p["why"]
    assert not any(f"inputs changed: ui/" in p["why"][i] for i in p["why"] if i != "gateway")


def test_a_dockerfile_change_rebuilds_that_image_and_its_children():
    p = _plan(["docker/Dockerfile.whisper"])
    assert _built(p) == ALWAYS | {"whisper"}, p["why"]
    p = _plan(["docker/Dockerfile.stunnel"])
    assert _built(p) == ALWAYS | {"stunnel"}, p["why"]


def test_a_shared_lock_change_rebuilds_every_image_that_installs_it():
    p = _plan(["docker/core-lock/requirements.txt"])
    assert _built(p) == ALWAYS | {"deps-core", "deps-base", "trellion", "sandbox", "worker"}, p["why"]
    assert "parent deps-core rebuilds" in p["why"]["worker"]
    p = _plan(["docker/ml-lock/requirements.txt"])
    assert _built(p) == ALWAYS | {"deps-base", "trellion"}, p["why"]


def test_shared_source_and_script_changes():
    assert _built(_plan(["src/noomesh/x.py"])) == ALWAYS | {"trellion", "sandbox", "worker"}
    assert _built(_plan(["config/tools.json"])) == ALWAYS | {"sandbox", "worker"}
    assert _built(_plan(["docker/voice_local.py"])) == ALWAYS | {"whisper", "piper"}
    assert _built(_plan(["node-agent-go/main.go"])) == ALWAYS


def test_a_change_outside_every_input_rebuilds_nothing_extra():
    p = _plan(["docs/guide.md", "noo-cli/src/main.rs", "tests/test_x.py"])
    assert _built(p) == ALWAYS and p["rc_tag"] == RC2


def test_a_release_lane_change_rebuilds_everything():
    for f in (".github/workflows/images-release.yml", "scripts/release-retag-plan.py",
              "scripts/release-image-inputs.json", ".dockerignore"):
        p = _plan([f, "gateway-rust/Cargo.lock"])
        assert not any(p["retag"].values()) and p["rc_tag"] == "", (f, p["why"])
        assert "release lane changed" in p["why"]["whisper"]


def test_a_base_image_digest_bump_is_a_dockerfile_change():
    # base images are pinned by digest INSIDE the Dockerfile, so the bump is a
    # change to the image's own Dockerfile
    assert 'sha256:' in (ROOT / IMAGES["piper"]["dockerfile"]).read_text()
    assert _built(_plan(["docker/Dockerfile.piper"])) == ALWAYS | {"piper"}


def test_unknown_or_missing_previous_rc_rebuilds_everything():
    assert not any(_plan(["x"], rcs=())["retag"].values())                      # no earlier rc
    assert not any(_plan(None)["retag"].values())                               # git could not diff
    assert not any(_plan(["x"], lock="garbage\n")["retag"].values())            # unreadable lock
    assert not any(_plan(["x"], table={"images": {}, "lane": []})["retag"].values())  # unknown images
    p = _plan(["x"], lock=LOCK.replace("whisper@sha256:whi\n", ""))               # image missing from the lock
    assert _built(p) == ALWAYS | {"whisper"}


def test_an_unreadable_table_rebuilds_everything(monkeypatch):
    def boom(*a, **k):
        raise OSError("gone")
    monkeypatch.setattr(P, "load_inputs", boom)
    p = P.plan(NEW, "o/r", {"trellion": "TRE"}, "t", "t", lock_text=LOCK, bases_text=BASES,
               tree_of=lambda r: {NEW: "T3", RC2: "T2", RC1: "T1"}[r], commit_of=lambda r: r,
               list_rcs=lambda f: [RC2, RC1], sib_tree=lambda *a: "T", changed_of=lambda a, b: ["x"])
    assert not any(p["retag"].values())


def test_a_final_never_uses_the_per_image_path():
    """A final without an equal-tree rc builds everything, as before."""
    p = _plan(["docs/x.md"], tag="stack-v1.2.3", trees={"stack-v1.2.3": "T9", RC2: "T2", RC1: "T1"})
    assert not any(p["retag"].values()) and p["rc_tag"] == ""


def test_an_equal_tree_still_wins_over_the_diff():
    trees = {NEW: "T2", RC2: "T2", RC1: "T1"}
    p = _plan(["gateway-rust/Cargo.lock"], trees=trees)   # diff would say gateway; tree says nothing changed
    assert p["rc_tag"] == RC2 and _built(p) == ALWAYS


def test_a_moved_sibling_still_rebuilds_what_it_feeds_in_per_image_mode():
    p = P.plan(NEW, "o/r", {"trellion": "TRE2"}, "t", "t", lock_text=LOCK, bases_text=BASES,
               tree_of=lambda r: {NEW: "T3", RC2: "T2", RC1: "T1"}[r], commit_of=lambda r: r,
               list_rcs=lambda f: [RC2, RC1], sib_tree=lambda repo, sha, tok: {"TRE": "a", "TRE2": "b"}[sha],
               changed_of=lambda a, b: ["gateway-rust/Cargo.lock"])
    assert _built(p) == ALWAYS | {"deps-base", "trellion"}, p["why"]


def test_the_real_0_6_10_rc6_to_rc7_diff_if_the_tags_exist():
    try:
        out = subprocess.run(["git", "diff", "--name-only", "--no-renames", "stack-v0.6.10-rc.6", "stack-v0.6.10-rc.7"],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("release tags not fetched")
    rebuild, lane = P.input_changes(out, TABLE)
    assert not lane and set(rebuild) == {"gateway"}, (out, rebuild)
