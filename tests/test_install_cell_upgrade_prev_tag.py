# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The upgrade cell's start: `upgrade_judge.py resolve` and the `prev_tag`
dispatch input (.github/workflows/install-matrix.yml -> upgrade.sh -> resolve).

Empty prev_tag: the newest noo-cli-vX.Y.Z final below the release under test,
as before. Set: strict (operator, "no dev path"): exactly noo-cli-vX.Y.Z,
strictly below the target's X.Y.Z, and a published, non-prerelease,
non-draft release; anything else refuses at resolve naming the rule, before
anything installs. The releases API is stubbed: no test reads the network.
"""
import importlib.util
import pathlib
import re
import subprocess
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
JUDGE = ROOT / "scripts" / "install-cell" / "upgrade_judge.py"
REPO = "example-org/example-repo"


def _load():
    spec = importlib.util.spec_from_file_location("upgrade_judge", JUDGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load()


def rel(tag, prerelease=False, draft=False):
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft}


RELEASES = [
    rel("noo-cli-v0.6.29-rc.1", prerelease=True),
    rel("noo-cli-v0.6.28"),
    rel("noo-cli-v0.6.27"),
    rel("noo-cli-v0.6.26"),
    rel("noo-cli-v0.6.25-rc.2", prerelease=True),
    rel("noo-cli-v0.6.24", prerelease=True),   # a final-shaped tag marked prerelease
    rel("noo-cli-v0.6.23", draft=True),        # a draft (visible to a token with push)
    rel("stack-v0.6.28"),
]


@pytest.fixture
def api(monkeypatch):
    """The releases API: the list, and /releases/tags/<tag> (404 -> None)."""
    calls = []

    def fake(repo, path, missing_ok=False):
        calls.append(path)
        assert repo == REPO
        if path == "releases?per_page=100":
            return api.releases
        tag = path.removeprefix("releases/tags/")
        assert missing_ok, "a single-tag read must tolerate a 404"
        return api.by_tag.get(tag)

    api.releases, api.by_tag, api.calls = list(RELEASES), {}, calls
    monkeypatch.setattr(M, "_api", fake)
    return api


def run(tmp_path, cli_tag, prev_tag=None):
    p, t = tmp_path / "prev", tmp_path / "target"
    args = [REPO, cli_tag, str(p), str(t)] + ([prev_tag] if prev_tag is not None else [])
    M.resolve(*args)
    return p.read_text(), t.read_text()


def refused(tmp_path, cli_tag, prev_tag, capsys):
    with pytest.raises(SystemExit) as e:
        run(tmp_path, cli_tag, prev_tag)
    assert not (tmp_path / "prev").exists() and not (tmp_path / "target").exists(), "nothing resolved"
    assert capsys.readouterr().out == "", "a refusal prints no start line"
    msg = str(e.value.code)
    assert msg.startswith("PREV_TAG %r refused (" % prev_tag), msg
    assert "\n" not in msg, "one line"
    return msg


# ── empty prev_tag: today's behaviour ────────────────────────────────────────

@pytest.mark.parametrize("prev", [None, ""], ids=["no-argument", "empty"])
def test_the_default_is_the_newest_final_below_the_target(api, tmp_path, capsys, prev):
    assert run(tmp_path, "noo-cli-v0.6.29-rc.1", prev) == ("noo-cli-v0.6.28", "noo-cli-v0.6.29-rc.1")
    assert capsys.readouterr().out == "previous final: noo-cli-v0.6.28; release under test: noo-cli-v0.6.29-rc.1\n"
    assert run(tmp_path, "noo-cli-v0.6.28", prev) == ("noo-cli-v0.6.27", "noo-cli-v0.6.28")
    # latest: the newest final, and the one before it
    assert run(tmp_path, "latest", prev) == ("noo-cli-v0.6.27", "noo-cli-v0.6.28")
    assert api.calls == ["releases?per_page=100"] * 3, "one list read each, nothing else"


# ── a valid prev_tag: chosen ─────────────────────────────────────────────────

def test_a_valid_prev_tag_is_the_start(api, tmp_path, capsys):
    assert run(tmp_path, "noo-cli-v0.6.29-rc.1", "noo-cli-v0.6.26") == ("noo-cli-v0.6.26", "noo-cli-v0.6.29-rc.1")
    assert capsys.readouterr().out == \
        "chosen start (prev_tag): noo-cli-v0.6.26; release under test: noo-cli-v0.6.29-rc.1\n"
    # below a final target, and below `latest` (the newest final)
    assert run(tmp_path, "noo-cli-v0.6.28", "noo-cli-v0.6.26")[0] == "noo-cli-v0.6.26"
    assert run(tmp_path, "latest", "noo-cli-v0.6.26") == ("noo-cli-v0.6.26", "noo-cli-v0.6.28")


def test_a_final_beyond_the_listed_page_is_read_by_its_tag(api, tmp_path):
    api.by_tag["noo-cli-v0.5.9"] = rel("noo-cli-v0.5.9")
    assert run(tmp_path, "noo-cli-v0.6.28", "noo-cli-v0.5.9")[0] == "noo-cli-v0.5.9"
    assert api.calls[-1] == "releases/tags/noo-cli-v0.5.9"


# ── every refusal names its rule ─────────────────────────────────────────────

@pytest.mark.parametrize("prev", [
    "noo-cli-v0.6.26-rc.1",        # an rc
    "noo-cli-v0.6.26-beta",        # any other suffix
    "dev",                         # a branch
    "refs/heads/noo-cli-v0.6.26",  # a ref
    "74482271",                    # a sha
    "latest",
    "noo-cli-v0.6.26.1",           # four-part (the project forbids them)
    "noo-cli-v0.6",                # two-part
    "v0.6.26",                     # not the CLI's tag
    " noo-cli-v0.6.26",
    "noo-cli-v0.6.26\n",
    "noo-cli-v0.6.26;id",
    "noo-cli-v0.6.2\u0666",         # a non-ASCII digit
], ids=["rc", "suffix", "branch", "ref", "sha", "latest", "four-part", "two-part", "bare-v", "space", "newline", "shell",
        "unicode-digit"])
def test_a_prev_tag_that_is_not_a_final_tag_is_refused_before_any_read(api, tmp_path, capsys, prev):
    msg = refused(tmp_path, "noo-cli-v0.6.29-rc.1", prev, capsys)
    assert "(pattern)" in msg and "noo-cli-vX.Y.Z" in msg, msg
    assert api.calls == [], "the pattern refuses before the releases API is read"


@pytest.mark.parametrize("cli_tag, prev", [
    ("noo-cli-v0.6.28", "noo-cli-v0.6.28"),        # equal
    ("noo-cli-v0.6.29-rc.1", "noo-cli-v0.6.29"),   # equal X.Y.Z: an rc's final is not below it
    ("noo-cli-v0.6.27", "noo-cli-v0.6.28"),        # above
    ("latest", "noo-cli-v0.6.28"),                 # equal to the newest final
], ids=["equal", "equal-to-rc-base", "above", "equal-latest"])
def test_a_prev_tag_not_below_the_target_is_refused(api, tmp_path, capsys, cli_tag, prev):
    msg = refused(tmp_path, cli_tag, prev, capsys)
    assert "(not below the target)" in msg, msg


def test_a_prev_tag_with_no_release_is_refused(api, tmp_path, capsys):
    msg = refused(tmp_path, "noo-cli-v0.6.29-rc.1", "noo-cli-v0.6.22", capsys)
    assert "(no release)" in msg and REPO in msg, msg
    assert api.calls[-1] == "releases/tags/noo-cli-v0.6.22", "looked it up by tag before refusing"


def test_a_prev_tag_whose_release_is_a_prerelease_is_refused(api, tmp_path, capsys):
    msg = refused(tmp_path, "noo-cli-v0.6.29-rc.1", "noo-cli-v0.6.24", capsys)
    assert "(prerelease)" in msg, msg


def test_a_prev_tag_whose_release_is_a_prerelease_beyond_the_page_is_refused(api, tmp_path, capsys):
    api.by_tag["noo-cli-v0.5.9"] = rel("noo-cli-v0.5.9", prerelease=True)
    assert "(prerelease)" in refused(tmp_path, "noo-cli-v0.6.28", "noo-cli-v0.5.9", capsys)


def test_a_prev_tag_whose_release_is_a_draft_is_refused(api, tmp_path, capsys):
    msg = refused(tmp_path, "noo-cli-v0.6.29-rc.1", "noo-cli-v0.6.23", capsys)
    assert "(draft)" in msg, msg


# ── the command line keeps its contract ──────────────────────────────────────

def test_the_command_line_takes_the_optional_prev_tag_and_refuses_it_with_exit_1(tmp_path):
    # a bad pattern refuses before any network read, so this runs offline
    r = subprocess.run([sys.executable, str(JUDGE), "resolve", REPO, "noo-cli-v0.6.29-rc.1",
                        str(tmp_path / "p"), str(tmp_path / "t"), "noo-cli-v0.6.26-rc.1"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 1 and "PREV_TAG 'noo-cli-v0.6.26-rc.1' refused (pattern)" in r.stderr, r
    r = subprocess.run([sys.executable, str(JUDGE), "resolve", REPO, "x", "p"], capture_output=True, text=True)
    assert r.returncode == 1 and "resolve OWNER/REPO TAG PREV TARGET [PREV_TAG]" in r.stderr


# ── the wiring: input -> env -> upgrade.sh -> resolve ────────────────────────

def _workflow():
    return yaml.safe_load((ROOT / ".github/workflows/install-matrix.yml").read_text())


def test_the_workflow_passes_prev_tag_through_env_never_into_a_script():
    doc = _workflow()
    on = doc.get("on") or doc.get(True)
    assert on["workflow_dispatch"]["inputs"]["prev_tag"]["default"] == ""
    steps = doc["jobs"]["upgrade"]["steps"]
    cell = [s for s in steps if "upgrade.sh" in (s.get("run") or "")]
    assert len(cell) == 1
    assert cell[0]["env"]["PREV_TAG"] == "${{ inputs.prev_tag }}"
    # no `${{ inputs.* }}` in any run: script of the file (script injection)
    for job in doc["jobs"].values():
        for s in job.get("steps") or []:
            assert not re.search(r"\$\{\{[^}]*\binputs\.", s.get("run") or ""), s


def test_upgrade_sh_hands_prev_tag_to_resolve_and_says_which_start_it_took():
    sh = (ROOT / "scripts/install-cell/upgrade.sh").read_text()
    assert re.search(r'upgrade_judge\.py" resolve "\$REPO" "\$CLI_TAG" "\$J/prev" "\$J/target" "\$PREV_TAG" \|\| finish', sh)
    assert 'START_KIND="chosen"' in sh and 'START_KIND="previous final"' in sh
    assert 'meta upgrade "$PREV ($START_KIND) -> $TARGET"' in sh
