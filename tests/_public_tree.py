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
