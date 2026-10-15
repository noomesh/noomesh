# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A skip in CI must be explained — pytest hooks that enforce it.

Why this lives in its own module instead of directly in conftest.py: the
end-to-end test in tests/test_ci_skip_guard.py runs a small INNER pytest
session (via the `pytester` fixture) to prove the hooks actually catch an
unlisted skip and actually pass an allow-listed one. That inner session
needs these hooks registered as a plugin without dragging in this repo's
real conftest.py (whose other fixtures import noomesh.*, none of which
exist inside pytester's throwaway sandbox). Keeping the hooks in an
importable module lets the inner test register `_ci_skip_guard` directly as
an in-process plugin object (`pytester.plugins.append(_ci_skip_guard)`),
while the real tests/conftest.py just imports the same hook functions so
pytest picks them up for the real suite. One implementation, two call
sites, no duplication.

The rule: a test that skips in CI guards nothing if nobody notices. PR #551
added an 18-case parity test gated on a binary the CI job never builds; all
18 skipped, silently, and the PR's evidence never ran. This module makes an
unexplained skip in CI a FAILED session instead of a quiet line in a log
nobody reads.

Strict-mode trigger (see `_strict_mode_enabled`):
  - GITHUB_ACTIONS == "true"   -> strict (this is what makes it "in CI only")
  - NOO_STRICT_SKIPS == "1"    -> strict, even outside CI (run it locally)
  - NOO_STRICT_SKIPS == "0"    -> never strict, overrides GITHUB_ACTIONS
  - otherwise                  -> not strict, hooks are no-ops

Allow-list format (one entry per line):

    <glob on nodeid> | <regex on skip reason> | <why this is OK in CI>

  - `#` starts a comment; blank lines are ignored.
  - All three fields are REQUIRED. A line with other than 3 `|`-separated
    fields, or with any field blank after stripping, is malformed — the
    session fails naming the file and line number, not the skip.
  - The nodeid glob is matched with `fnmatch.fnmatch` against the pytest
    nodeid (e.g. "tests/test_pki_rotation.py::TestClusterCA::*").
  - The reason regex is matched with `re.search` against the skip reason
    pytest recorded for that item (a module-level `pytestmark` skip reports
    one item at a time, each with the same reason, so one glob covering the
    whole file plus one reason regex is normally enough for a whole module).

Staleness: an allow-list entry that matched nothing this run is dead
weight — it will one day excuse a skip nobody meant to allow. It is
REPORTED on every full run but FAILS the session only when
NOO_STRICT_SKIPS=1 is set explicitly (a deliberate local audit). In CI it
is a warning: what skips depends on the runner's tools and on the base
commit (a test that skips until a sibling PR merges; two self-hosted
runners that can differ), so an entry can be correct on one run and
unused on the next — failing CI on that would be flaky, and flaky guards
get disabled. Staleness is only considered on a FULL run of the whole tests/ tree (no -k, no -m, and the path
arguments are empty or exactly "tests"/"tests/"), because a narrowed run
(`pytest tests/test_foo.py` or `-k something`) legitimately never touches
most of the allow-list and that must not look like staleness.

Path resolution: the allow-list lives next to the conftest.py that wires
these hooks up — tests/ci_skip_allowlist.txt relative to tests/conftest.py —
never the process cwd. `TESTS_DIR` below is a module-level slot that
conftest.py sets from its own `__file__` on import; the pytester-based
end-to-end test overrides it to point at pytester's throwaway sandbox
instead, so "file absent" / "file malformed" can be exercised in isolation
without touching the real allow-list.

State isolation: skip collection is kept on a small plugin OBJECT created
fresh in `pytest_configure` and registered into that session's own
pluginmanager (`config.pluginmanager.register(...)`), rather than in a
module-level dict. tests/test_ci_skip_guard.py's end-to-end case runs a
nested pytest session (outer real suite -> inner pytester suite) while the
outer session is still mid-run; a module-level dict would be shared process
state and the inner run would clobber the outer run's in-progress
collection. Each session's own Config/PluginManager is genuinely separate,
so a plugin instance stashed on `config` is naturally scoped correctly.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

ALLOWLIST_FILENAME = "ci_skip_allowlist.txt"

# Set by tests/conftest.py at import time to Path(__file__).resolve().parent
# (i.e. the tests/ directory). The pytester end-to-end test in
# tests/test_ci_skip_guard.py points this at its own sandbox directory
# instead, so the hooks read an isolated allow-list rather than the real one.
TESTS_DIR: Optional[Path] = None


class AllowlistError(Exception):
    """A problem with the allow-list file itself (missing or malformed)."""


@dataclass
class AllowlistEntry:
    nodeid_glob: str
    reason_pattern: str
    reason_re: "re.Pattern[str]"
    justification: str
    lineno: int
    raw: str
    used: bool = False


def allowlist_path() -> Path:
    if TESTS_DIR is None:
        # Should not happen in the real suite — conftest.py sets this at
        # import time, before any hook can fire. Fall back to this file's
        # own directory (tests/) so a misconfiguration still points
        # somewhere sane instead of silently reading the process cwd.
        return Path(__file__).resolve().parent / ALLOWLIST_FILENAME
    return TESTS_DIR / ALLOWLIST_FILENAME


def parse_allowlist(text: str, source: Path) -> list[AllowlistEntry]:
    """Parse the allow-list file. Raises AllowlistError naming the bad line."""
    entries: list[AllowlistEntry] = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) != 3:
            raise AllowlistError(
                f"{source}:{i}: malformed allow-list line (need exactly 3 "
                f"'|'-separated fields: glob | reason regex | justification): "
                f"{raw_line!r}"
            )
        nodeid_glob, reason_pattern, justification = (p.strip() for p in parts)
        if not nodeid_glob or not reason_pattern or not justification:
            raise AllowlistError(
                f"{source}:{i}: malformed allow-list line (a field is empty — "
                f"glob, reason regex, and justification are all required): "
                f"{raw_line!r}"
            )
        try:
            reason_re = re.compile(reason_pattern)
        except re.error as exc:
            raise AllowlistError(
                f"{source}:{i}: bad regex in reason field {reason_pattern!r}: {exc}"
            ) from exc
        entries.append(
            AllowlistEntry(
                nodeid_glob=nodeid_glob,
                reason_pattern=reason_pattern,
                reason_re=reason_re,
                justification=justification,
                lineno=i,
                raw=raw_line,
            )
        )
    return entries


def load_allowlist() -> list[AllowlistEntry]:
    path = allowlist_path()
    if not path.is_file():
        raise AllowlistError(
            f"ci-skip-guard: allow-list file missing at {path} — in CI, an "
            f"absent allow-list means every skip is unexplained, not that "
            f"every skip is allowed. Create it (see docs/development/"
            f"developer-guide.md, 'A skip in CI must be explained')."
        )
    return parse_allowlist(path.read_text(), path)


def match_entry(
    entries: list[AllowlistEntry], nodeid: str, reason: str
) -> Optional[AllowlistEntry]:
    for entry in entries:
        if fnmatch.fnmatch(nodeid, entry.nodeid_glob) and entry.reason_re.search(reason):
            return entry
    return None


def _strict_mode_enabled() -> bool:
    override = os.environ.get("NOO_STRICT_SKIPS")
    if override == "0":
        return False
    if override == "1":
        return True
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _is_full_run(config) -> bool:
    """True iff this run collected the whole tests/ tree.

    Conservative on purpose: anything that could have narrowed collection
    (-k, -m, or explicit non-"tests" path args) means "not a full run", so
    staleness is only enforced when every allow-list entry had a real
    chance to match something.
    """
    args = list(getattr(config, "invocation_params", config).args)
    for a in args:
        if a == "-k" or a.startswith("-k") or a == "--keyword":
            return False
        if a == "-m" or a.startswith("-m"):
            return False
    path_args = [a for a in args if not a.startswith("-")]
    return len(path_args) == 0 or set(path_args) <= {"tests", "tests/"}


def _skip_reason(report) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr)


# eq=False: pluggy (subset_hook_caller) puts registered plugins in a set; a
# default dataclass sets __hash__ = None and crashes the session with
# "unhashable type" on newer pluggy. Plugins need identity hash/eq.
@dataclass(eq=False)
class _SkipCollector:
    """Per-session skip collector, registered fresh in pytest_configure.

    A plugin instance rather than a module-level dict: each pytest session
    (including a nested pytester session started mid-way through the outer
    real suite, as tests/test_ci_skip_guard.py's end-to-end case does) gets
    its own Config/PluginManager, so state hung off the instance is
    correctly scoped per session with no risk of one run clobbering another.
    """

    seen: dict = field(default_factory=dict)  # nodeid -> reason

    def pytest_runtest_logreport(self, report):
        if not report.skipped:
            return
        # xfail-that-failed-as-expected also reports outcome "skipped" but
        # carries `wasxfail`; it ran and behaved as declared, so it is not
        # a skip in the sense this guard cares about — leave it alone.
        if getattr(report, "wasxfail", None) is not None:
            return
        if report.when not in ("setup", "call"):
            return
        # setup-phase skip wins if both somehow fire; in practice a setup
        # skip means "call" never runs, so there is exactly one report.
        self.seen.setdefault(report.nodeid, _skip_reason(report))


def pytest_configure(config):
    collector = _SkipCollector()
    config._ci_skip_guard_collector = collector
    config.pluginmanager.register(collector, name="ci-skip-guard-collector")


def pytest_sessionfinish(session, exitstatus):
    if not _strict_mode_enabled():
        return

    config = session.config
    tr = config.pluginmanager.get_plugin("terminalreporter")

    def emit(line: str) -> None:
        if tr is not None:
            tr.write_line(line)
        else:  # pragma: no cover - defensive, tr is present in practice
            print(line)

    try:
        entries = load_allowlist()
    except AllowlistError as exc:
        emit(f"ci-skip-guard: FAIL - {exc}")
        session.exitstatus = 1
        return

    collector = getattr(config, "_ci_skip_guard_collector", None)
    seen: dict = collector.seen if collector is not None else {}

    unexplained: list[str] = []
    for nodeid, reason in seen.items():
        entry = match_entry(entries, nodeid, reason)
        if entry is None:
            unexplained.append(f"{nodeid}: {reason}")
        else:
            entry.used = True

    stale: list[str] = []
    if _is_full_run(config):
        stale = [
            f"{e.raw!r} ({allowlist_path().name}:{e.lineno})"
            for e in entries
            if not e.used
        ]

    # Always say that the guard ran: silence is also what a guard that never
    # switched on looks like, and the whole point is not to trust that.
    emit("")
    emit(
        f"ci-skip-guard: active — {len(seen)} skip(s), "
        f"{len(seen) - len(unexplained)} explained by "
        f"{sum(1 for e in entries if e.used)}/{len(entries)} allow-list entries"
    )

    if not unexplained and not stale:
        return

    stale_fails = os.environ.get("NOO_STRICT_SKIPS") == "1"
    emit("")
    if unexplained or stale_fails:
        emit("ci-skip-guard: FAIL - skips in CI must be explained")
    else:
        emit("ci-skip-guard: WARNING - allow-list entries matched nothing")
    if unexplained:
        emit("")
        emit("Unexplained skips (no matching tests/ci_skip_allowlist.txt entry):")
        for line in unexplained:
            emit(f"  {line}")
        emit(
            "Make the test run in CI, or add an allow-list entry with a "
            "real justification for why skipping is acceptable there."
        )
    if stale:
        emit("")
        emit("Stale allow-list entries (matched nothing in this full run):")
        for line in stale:
            emit(f"  {line}")
        emit(
            "Remove the entry, or narrow it - a rule matching nothing today "
            "will one day excuse a skip nobody meant to allow."
            + ("" if stale_fails else " (warning only here; NOO_STRICT_SKIPS=1 makes it fail)")
        )
    emit("")
    if unexplained or stale_fails:
        session.exitstatus = 1
