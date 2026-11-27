# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""What a test run leaves out, kept in ONE place every runner reads.

test-core (ci.yml) and the mutants workflow's python lane
(scripts/ci-mutants.py) both run `pytest tests/`. Each used to carry its own
idea of what to leave out, and only test-core had a list, so the mutants lane
started from a red base on dev and every unscoped verdict was void. Now:

  * A test that needs an input this tree does not have (a script, a sibling
    checkout) decides that itself and skips with a reason that starts with
    SELF_SKIP_PREFIX. No runner passes `--deselect` for it.
  * What cannot decide for itself (a module that imports the trellion package
    at collection time) is listed below and applied from tests/conftest.py,
    keyed on the same TRELLION_PUBLIC variable both runners already set.
  * Every self-skip is counted and named in the pytest summary, so a rise in
    the count is seen.
  * test-core sets NOO_SUITE_BOUNDS=1, and a run that collected fewer tests
    than MIN_COLLECTED or skipped more than MAX_SKIPPED fails (below), so a
    quiet shrinkage of the suite cannot pass the gate.
"""

from __future__ import annotations

import os
from pathlib import Path

SELF_SKIP_PREFIX = "not in this tree:"
TRELLION_ENV = "TRELLION_PUBLIC"

# Import the trellion package at collection time: not collected at all while
# trellion is not public.
NEEDS_TRELLION_IGNORE = (
    "test_agent_messaging_client.py",
    "test_backend_profiles.py",
    "test_evidence.py",
    "test_memory_shim_providers.py",
    "test_parallel_collab.py",
    "test_rag_orchestrator.py",
    "test_rag_verifier.py",
    "test_workflow.py",
)

# Need the trellion package at run time (the [trellion] extra): collected, then
# deselected (and reported as deselected) while trellion is not public.
NEEDS_TRELLION_DESELECT = (
    "test_persona_scoping.py",
    "test_walks_worker.py",
    "test_snapshot_audience.py",
)


def trellion_absent(environ=os.environ) -> bool:
    """True when the runner says trellion is not public. Unset means a local
    run on a box that has it: nothing is left out."""
    return TRELLION_ENV in environ and environ[TRELLION_ENV] != "true"


def collect_ignore_list(environ=os.environ) -> list[str]:
    return list(NEEDS_TRELLION_IGNORE) if trellion_absent(environ) else []


def pytest_collection_modifyitems(config, items):
    if not trellion_absent():
        return
    names = set(NEEDS_TRELLION_DESELECT)
    gone = [i for i in items if Path(str(i.fspath)).name in names]
    if gone:
        config.hook.pytest_deselected(items=gone)
        items[:] = [i for i in items if i not in gone]


def self_skips(terminalreporter) -> list[tuple[str, str]]:
    out = []
    for rep in terminalreporter.stats.get("skipped", []):
        lr = rep.longrepr
        reason = lr[2] if isinstance(lr, tuple) and len(lr) == 3 else str(lr)
        if reason.startswith("Skipped: "):
            reason = reason[len("Skipped: "):]
        if reason.startswith(SELF_SKIP_PREFIX):
            out.append((rep.nodeid, reason))
    return out


def pytest_terminal_summary(terminalreporter):
    found = self_skips(terminalreporter)
    if not found:
        return
    terminalreporter.section(f"tests that skipped themselves ({SELF_SKIP_PREFIX!r}): {len(found)}")
    for nodeid, reason in sorted(found):
        terminalreporter.line(f"  {nodeid}  --  {reason}")


# Suite-size bounds, enforced when the runner sets NOO_SUITE_BOUNDS=1 (test-core).
# Observed 2026-11-27 on this PR's own `test-core (advisory)` run (full suite,
# TRELLION_PUBLIC=true, run 45927667006): 5826 passed + 120 skipped = 5946 run.
# Set a little inside those figures; raise MIN_COLLECTED as the suite grows and
# lower MAX_SKIPPED as skips are removed. The floor applies only when trellion
# is public (otherwise eleven modules are left out on purpose).
BOUNDS_ENV = "NOO_SUITE_BOUNDS"
MIN_COLLECTED = 5850
MAX_SKIPPED = 135


def suite_size_problem(collected: int, skipped: int, environ=os.environ) -> str | None:
    if collected < MIN_COLLECTED and not trellion_absent(environ):
        return f"the run collected {collected} tests, fewer than the floor {MIN_COLLECTED}: tests were left out"
    if skipped > MAX_SKIPPED:
        return f"{skipped} tests skipped, more than the ceiling {MAX_SKIPPED}: tests are skipping themselves"
    return None


def pytest_sessionfinish(session, exitstatus):
    if os.environ.get(BOUNDS_ENV) != "1" or hasattr(session.config, "workerinput"):
        return
    tr = session.config.pluginmanager.get_plugin("terminalreporter")
    if tr is None:
        return
    st = tr.stats
    ran = sum(len(st.get(k, [])) for k in ("passed", "failed", "skipped", "error", "xfailed", "xpassed"))
    problem = suite_size_problem(ran, len(st.get("skipped", [])))
    tr.write_line(f"suite-size guard: {ran} run, {len(st.get('skipped', []))} skipped"
                  f" (floor {MIN_COLLECTED}, ceiling {MAX_SKIPPED}): " + (problem or "ok"))
    if problem:
        session.exitstatus = 1
