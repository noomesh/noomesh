# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Retagging moves documents between audiences, so it is an access-control
change wearing maintenance clothes.

Two properties matter more than the SQL: a caller cannot tag into an
audience it could not write to itself, and nothing is written unless the
caller asked for it in as many words.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAG = ROOT / "src/noomesh/workers/rag.py"


def _handler_src() -> str:
    tree = ast.parse(RAG.read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_rag_retag":
            src = ast.get_source_segment(RAG.read_text(), node) or ""
            doc = ast.get_docstring(node) or ""
            return src.replace(doc, "") if doc else src
    raise AssertionError("_rag_retag is gone; this guard is stale")


def test_the_subject_is_registered():
    import os

    os.environ["NOO_WORKER_SURFACES"] = "ml"
    import noomesh.workers  # noqa: F401
    from noomesh.workers import registry

    assert "worker.rag.retag" in registry.all_handlers()


def test_it_is_a_dry_run_unless_asked():
    """A mistyped glob should cost a printout, not a disclosure."""
    src = _handler_src()
    assert 'request.get("apply")' in src
    assert '"status": "dry-run"' in src


def test_the_empty_selector_is_refused():
    """"Everything" is a defensible thing to ask for, but never by omission."""
    src = _handler_src()
    assert "if not match and not doc_ids:" in src


def test_target_roles_are_clamped_to_what_the_caller_could_write():
    """The ingest rule, reused rather than restated. An operator must not be
    able to publish someone's private documents into a team they are not in."""
    src = _handler_src()
    assert "_writable_kb_roles" in src


def test_a_refused_role_is_named_not_silently_dropped():
    """Dropping it would retag the documents into a NARROWER audience than
    asked for and report success — the operator would believe the wider
    audience had it."""
    src = _handler_src()
    assert "refused" in src
    assert "not yours to tag into" in src


def test_only_untagged_defaults_true():
    src = _handler_src()
    assert "only_untagged = True if only_untagged is None else bool(only_untagged)" in src


def test_relabel_is_reachable():
    """The requirement is not backfill-only: a source rule changing is a
    normal event, and documents that went to the wrong team must be fixable."""
    src = _handler_src()
    assert "only_untagged=only_untagged" in src, (
        "the handler no longer forwards only_untagged, so relabel is unreachable"
    )


@pytest.mark.parametrize(
    "glob,like",
    [
        ("gdrive://*", "gdrive://%"),
        ("a?b", "a_b"),
        ("100%_real", "100\\%\\_real"),
    ],
)
def test_the_glob_becomes_a_like_pattern_with_wildcards_escaped(glob, like):
    """The caller writes a glob because that is what `kb.source_roles` takes.
    An unescaped `%` in a source_uri would silently widen the selection."""
    p = glob.replace("\\", "\\\\").replace("%", "\\%")
    p = p.replace("_", "\\_").replace("*", "%").replace("?", "_")
    assert p == like


def test_the_route_attaches_the_requester():
    """Without it the worker cannot clamp, and `_resolve_kb_roles` would see
    no principal at all."""
    route = (ROOT / "gateway-rust/src/routes/knowledge.rs").read_text()
    body = route[route.index("async fn rag_retag") : route.index("async fn rag_ingest")]
    assert "attach_requester" in body


def test_the_cli_refuses_to_retag_everything_by_omission():
    cli = (ROOT / "noo-cli/src/commands/rag.rs").read_text()
    body = cli[cli.index("pub fn rag_retag") :]
    body = body[: body.index("\n}\n")]
    assert "refusing to retag everything by omission" in body
    assert '"--apply" => apply = true' in body
