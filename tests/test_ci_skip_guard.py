# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for tests/_ci_skip_guard.py — "a skip in CI must be explained".

Two layers:

  - Unit tests for the allow-list parser and the glob/regex matcher
    (`parse_allowlist`, `load_allowlist`, `match_entry`) — no pytest session
    involved, just the pure functions.
  - An end-to-end layer using the `pytester` fixture: it runs a tiny INNER
    pytest session with `tests/_ci_skip_guard` registered as a plugin
    (`pytester.runpytest_inprocess(..., plugins=[_ci_skip_guard])`) and
    `GITHUB_ACTIONS=true` set, and asserts on the inner session's
    outcome/output. This is the only way to prove the *hooks*
    (pytest_configure / the logreport collector / pytest_sessionfinish)
    actually wire together end to end, not just that the helper functions
    are individually correct.

`pytest_plugins = ["pytester"]` below enables the `pytester` fixture. It has
to live in this test module rather than in tests/conftest.py: pytest only
allows `pytest_plugins` in the *rootdir* conftest.py, and tests/conftest.py
is not that file (the rootdir is the repo root, which has no conftest.py of
its own) — declaring it there raises a collection error. A test module has
no such restriction, and the repo has no prior `pytester` usage to match, so
this is the plain, documented way to opt in.

Why the inner suite gets `_ci_skip_guard` as a plugin OBJECT rather than a
`-p tests._ci_skip_guard` string: the inner suite runs `runpytest_inprocess`
against pytester's own throwaway sandbox directory, which is not on
`sys.path` as a place `tests._ci_skip_guard` could be imported from. Passing
the already-imported module object via `pytester.plugins` sidesteps that —
pytest registers whatever hook-bearing object it's given, name or module.

`TESTS_DIR` is monkeypatched per-test to point at `pytester.path` (or a
subdirectory of it) so each inner run reads an ISOLATED allow-list instead
of this repo's real tests/ci_skip_allowlist.txt.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tests import _ci_skip_guard as guard

pytest_plugins = ["pytester"]


# ─────────────────────────────────────────────────────────────────────────
# Unit tests: parsing
# ─────────────────────────────────────────────────────────────────────────


def test_parse_valid_line():
    text = "tests/foo.py::* | needs docker | host has no docker daemon in CI\n"
    entries = guard.parse_allowlist(text, Path("allowlist.txt"))
    assert len(entries) == 1
    e = entries[0]
    assert e.nodeid_glob == "tests/foo.py::*"
    assert e.reason_pattern == "needs docker"
    assert e.justification == "host has no docker daemon in CI"
    assert e.lineno == 1
    assert e.used is False


def test_parse_ignores_comments_and_blank_lines():
    text = textwrap.dedent(
        """\
        # a comment
        tests/foo.py::* | reason | why

        # another comment
        """
    )
    entries = guard.parse_allowlist(text, Path("allowlist.txt"))
    assert len(entries) == 1


def test_parse_missing_justification_is_an_error_naming_the_line():
    text = "tests/ok.py::* | ok reason | ok justification\n\ntests/foo.py::* | reason |   \n"
    with pytest.raises(guard.AllowlistError) as excinfo:
        guard.parse_allowlist(text, Path("allowlist.txt"))
    msg = str(excinfo.value)
    # Line 3 (a valid line 1, a blank line 2) is the malformed one.
    assert ":3:" in msg
    assert "allowlist.txt" in msg


def test_parse_wrong_field_count_is_an_error_naming_the_line():
    text = "one field only\n"
    with pytest.raises(guard.AllowlistError) as excinfo:
        guard.parse_allowlist(text, Path("allowlist.txt"))
    assert ":1:" in str(excinfo.value)


def test_parse_bad_regex_is_an_error_naming_the_line():
    text = "tests/foo.py::* | ( unbalanced | why\n"
    with pytest.raises(guard.AllowlistError) as excinfo:
        guard.parse_allowlist(text, Path("allowlist.txt"))
    assert ":1:" in str(excinfo.value)
    assert "regex" in str(excinfo.value)


def test_parse_pipe_in_glob_or_reason_is_still_three_fields_by_position():
    # A naive split("|") means a literal "|" inside the glob/reason breaks
    # the 3-field contract — documenting that here so it stays a known
    # constraint rather than a silent surprise.
    text = "tests/foo.py::* | a|b | why\n"
    with pytest.raises(guard.AllowlistError):
        guard.parse_allowlist(text, Path("allowlist.txt"))


# ─────────────────────────────────────────────────────────────────────────
# Unit tests: load_allowlist (file-absent behaviour) and matching
# ─────────────────────────────────────────────────────────────────────────


def test_load_allowlist_missing_file_names_the_path(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "TESTS_DIR", tmp_path)
    with pytest.raises(guard.AllowlistError) as excinfo:
        guard.load_allowlist()
    assert str(tmp_path / guard.ALLOWLIST_FILENAME) in str(excinfo.value)


def test_load_allowlist_reads_relative_to_tests_dir_not_cwd(tmp_path, monkeypatch):
    (tmp_path / guard.ALLOWLIST_FILENAME).write_text("tests/x.py::* | r | why\n")
    monkeypatch.setattr(guard, "TESTS_DIR", tmp_path)
    monkeypatch.chdir(tmp_path.parent)  # cwd deliberately somewhere else
    entries = guard.load_allowlist()
    assert len(entries) == 1


def test_match_entry_glob_and_regex_both_must_hold():
    entries = guard.parse_allowlist(
        "tests/foo.py::* | needs docker | ok\n", Path("a.txt")
    )
    assert guard.match_entry(entries, "tests/foo.py::test_a", "needs docker") is not None
    # Right nodeid, wrong reason.
    assert guard.match_entry(entries, "tests/foo.py::test_a", "needs npx") is None
    # Right reason, wrong nodeid.
    assert guard.match_entry(entries, "tests/bar.py::test_a", "needs docker") is None


def test_match_entry_reason_is_search_not_fullmatch():
    entries = guard.parse_allowlist(
        "tests/foo.py::* | docker | ok\n", Path("a.txt")
    )
    assert (
        guard.match_entry(
            entries, "tests/foo.py::test_a", "needs docker daemon on this host"
        )
        is not None
    )


def test_is_full_run_detection(monkeypatch):
    class _Cfg:
        def __init__(self, args):
            self.invocation_params = type("IP", (), {"args": args})()

    assert guard._is_full_run(_Cfg([]))
    assert guard._is_full_run(_Cfg(["tests"]))
    assert guard._is_full_run(_Cfg(["tests/"]))
    assert not guard._is_full_run(_Cfg(["tests/test_foo.py"]))
    assert not guard._is_full_run(_Cfg(["-k", "something"]))
    assert not guard._is_full_run(_Cfg(["-kfoo"]))
    assert not guard._is_full_run(_Cfg(["-m", "not integration"]))


# ─────────────────────────────────────────────────────────────────────────
# End-to-end tests via pytester
# ─────────────────────────────────────────────────────────────────────────


def _write_allowlist(pytester, content: str) -> None:
    (pytester.path / guard.ALLOWLIST_FILENAME).write_text(content)


def _run_inner(pytester, monkeypatch, *args):
    """Run the inner suite in-process with the guard plugin + GITHUB_ACTIONS=true.

    `pytester.runpytest_inprocess` forwards to `Pytester.inline_run`, which
    only honours a `plugins=` KEYWORD argument — the documented
    `pytester.plugins` LIST attribute is read by `parseconfig`/
    `runpytest_subprocess`, not by the in-process path, so appending to it
    here would silently register nothing. Passing `plugins=[guard]`
    straight through is what actually wires `_ci_skip_guard`'s hooks into
    the inner session.
    """
    monkeypatch.setattr(guard, "TESTS_DIR", pytester.path)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("NOO_STRICT_SKIPS", raising=False)
    return pytester.runpytest_inprocess(*args, plugins=[guard])


def test_e2e_allowlisted_skip_passes(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        def test_skipped():
            pytest.skip("host has no docker")

        def test_ok():
            assert True
        """
    )
    _write_allowlist(
        pytester,
        "test_e2e_allowlisted_skip_passes.py::* | no docker | no docker daemon on CI runners\n",
    )
    result = _run_inner(pytester, monkeypatch)
    result.assert_outcomes(passed=1, skipped=1)
    assert result.ret == 0



def test_e2e_guard_announces_itself_when_active(pytester, monkeypatch):
    """A clean strict run must still print a line — silence would look the
    same as a guard that never switched on."""
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    _write_allowlist(pytester, "# no entries\n")
    result = _run_inner(pytester, monkeypatch)
    assert result.ret == 0
    result.stdout.fnmatch_lines(["*ci-skip-guard: active*0 skip(s)*"])

def test_e2e_unlisted_skip_fails_the_session(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        def test_skipped():
            pytest.skip("mystery reason nobody explained")
        """
    )
    _write_allowlist(pytester, "# nothing allow-listed\n")
    result = _run_inner(pytester, monkeypatch)
    assert result.ret != 0
    result.stdout.fnmatch_lines(
        [
            "*ci-skip-guard: FAIL*",
            "*::test_skipped: *mystery reason nobody explained*",
        ]
    )


def test_e2e_whole_module_skip_reports_every_item_once(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        pytestmark = pytest.mark.skip(reason="needs a live gateway")

        def test_a():
            assert True

        def test_b():
            assert True
        """
    )
    _write_allowlist(pytester, "# nothing allow-listed\n")
    result = _run_inner(pytester, monkeypatch)
    assert result.ret != 0
    out = "\n".join(result.outlines)
    # pytest prefixes the recorded skip reason with "Skipped: ".
    assert out.count("test_a: Skipped: needs a live gateway") == 1
    assert out.count("test_b: Skipped: needs a live gateway") == 1


def test_e2e_stale_entry_warns_in_ci_on_a_full_run(pytester, monkeypatch):
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    _write_allowlist(
        pytester,
        "tests/nothing_matches_this.py::* | reason | this never fires\n",
    )
    result = _run_inner(pytester, monkeypatch)  # no -k / -m / path args => full run
    # In CI a stale entry is a warning, not a failure: what skips depends on
    # the runner's tools and the base commit, so failing would be flaky.
    assert result.ret == 0
    result.stdout.fnmatch_lines(["*WARNING*", "*Stale allow-list entries*"])


def test_e2e_stale_entry_fails_an_explicit_local_strict_run(pytester, monkeypatch):
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    _write_allowlist(
        pytester,
        "tests/nothing_matches_this.py::* | reason | this never fires\n",
    )
    monkeypatch.setattr(guard, "TESTS_DIR", pytester.path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("NOO_STRICT_SKIPS", "1")
    result = pytester.runpytest_inprocess(plugins=[guard])
    assert result.ret != 0
    result.stdout.fnmatch_lines(["*FAIL*", "*Stale allow-list entries*"])


def test_e2e_stale_entry_is_not_enforced_on_a_narrowed_run(pytester, monkeypatch):
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    _write_allowlist(
        pytester,
        "tests/nothing_matches_this.py::* | reason | this never fires\n",
    )
    result = _run_inner(pytester, monkeypatch, "-k", "test_ok")
    assert result.ret == 0


def test_e2e_missing_allowlist_file_fails_naming_the_path(pytester, monkeypatch):
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    # Deliberately do not write ci_skip_allowlist.txt.
    result = _run_inner(pytester, monkeypatch)
    assert result.ret != 0
    result.stdout.fnmatch_lines([f"*allow-list file missing*{guard.ALLOWLIST_FILENAME}*"])


def test_e2e_malformed_line_fails_naming_the_line(pytester, monkeypatch):
    pytester.makepyfile(
        """
        def test_ok():
            assert True
        """
    )
    _write_allowlist(pytester, "this is not a valid entry\n")
    result = _run_inner(pytester, monkeypatch)
    assert result.ret != 0
    result.stdout.fnmatch_lines([f"*{guard.ALLOWLIST_FILENAME}:1:*malformed*"])


def test_e2e_xfail_is_not_treated_as_a_skip(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        @pytest.mark.xfail(reason="known broken")
        def test_expected_to_fail():
            assert False
        """
    )
    _write_allowlist(pytester, "# nothing allow-listed — xfail must not need an entry\n")
    result = _run_inner(pytester, monkeypatch)
    assert result.ret == 0


def test_e2e_not_strict_when_env_absent(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        def test_skipped():
            pytest.skip("unexplained, but we are not in CI")
        """
    )
    # No allow-list file at all, and GITHUB_ACTIONS unset by not calling
    # _run_inner's env setup — the guard must be a complete no-op.
    monkeypatch.setattr(guard, "TESTS_DIR", pytester.path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("NOO_STRICT_SKIPS", raising=False)
    result = pytester.runpytest_inprocess(plugins=[guard])
    result.assert_outcomes(skipped=1)
    assert result.ret == 0


def test_e2e_noo_strict_skips_0_disables_even_in_ci(pytester, monkeypatch):
    pytester.makepyfile(
        """
        import pytest

        def test_skipped():
            pytest.skip("unexplained")
        """
    )
    monkeypatch.setattr(guard, "TESTS_DIR", pytester.path)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("NOO_STRICT_SKIPS", "0")
    result = pytester.runpytest_inprocess(plugins=[guard])
    assert result.ret == 0
