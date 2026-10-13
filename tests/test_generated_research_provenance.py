# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Generated research carries provenance and the `generated` marker.

Both writers of machine-authored documents shipped with the same defect, and
neither was caught by anything: the field simply was not sent, so ingestion
succeeded and the document landed anonymous.

  research pipeline   passed only {title, text} through `kb_ingest`
  heartbeat reports   sent `source` where the worker reads `source_uri`

`source_uri` is not decoration. It is the dedup key (`docs.source_uri`) AND
what `kb_roles` glob-matches to assign an audience. Without it a document has
no dedup key and matches no role rule, so it falls through to
`kb.default_roles` — indistinguishable from a human-authored one.

Measured on the controller before the fix (2026-08-16):

    research note      211 rows,  3 distinct titles   (~70 copies each)
    heartbeat report    29 rows, 29 distinct titles
    all of them         source_uri EMPTY, roles ["company"]

211 of 573 documents — 37% of the KB — were near-duplicate generated text
competing with real sources at retrieval time. That is the "agent regurgitates
its own previous research" failure, already happening rather than hypothetical.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


class TestResearchPipelineProvenance:
    def test_ingest_step_sets_a_source_uri(self):
        """No source_uri means no dedup key — the direct cause of ~70 copies
        of each note."""
        src = (ROOT / "src/noomesh/pipeline/research.py").read_text()
        assert '"source_uri"' in src, "the kb_ingest step must set source_uri"
        assert "research://" in src, "source_uri should carry a research:// scheme for the role rule"

    def test_source_uri_is_scoped_per_day_not_per_run(self):
        """Per-run would reintroduce unbounded duplication; a stable
        per-topic key would collapse the whole history into one row."""
        src = (ROOT / "src/noomesh/pipeline/research.py").read_text()
        assert "%Y-%m-%d" in src

    def test_notes_are_tagged_generated(self):
        src = (ROOT / "src/noomesh/pipeline/research.py").read_text()
        assert '"roles": ["generated"]' in src

    def test_slug_is_stable_and_uri_safe(self):
        """The dedup key changes if the slug does, and duplicates come back."""
        from noomesh.pipeline.research import _slug

        topic = "local LLM inference (vLLM, llama.cpp), knowledge graphs"
        assert _slug(topic) == _slug(topic)
        assert re.fullmatch(r"[a-z0-9-]+", _slug(topic))
        assert not _slug(topic).startswith("-") and not _slug(topic).endswith("-")
        assert _slug("") == "topic"          # never empty — that would be a shared key
        assert len(_slug("x" * 500)) <= 80


class TestKbIngestCapabilityForwards:
    """The capability sat between the pipeline and the worker and dropped
    everything but title/text, so setting source_uri upstream would have been
    silently discarded."""

    def test_forwards_source_uri_and_roles(self):
        src = (ROOT / "src/noomesh/pipeline/capabilities.py").read_text()
        block = src[src.index('@capability("kb_ingest")'):src.index('@capability("model_map")')]
        assert 'args["source_uri"]' in block
        assert 'args["roles"]' in block


class TestHeartbeatReportProvenance:
    def test_sends_source_uri_not_only_source(self):
        """`source` and `source_uri` are different fields. Sending only the
        first is why 29 reports have an empty provenance column."""
        src = (ROOT / "gateway-rust/src/heartbeat_actions.rs").read_text()
        block = src[src.index("pub async fn ingest_report_to_kb"):]
        block = block[:block.index("\npub ") if "\npub " in block[1:] else len(block)]
        assert '"source_uri": source_uri' in block

    def test_reports_are_tagged_generated(self):
        src = (ROOT / "gateway-rust/src/heartbeat_actions.rs").read_text()
        assert '"roles": ["generated"]' in src


class TestGeneratedIsOptIn:
    """`generated` is the ONLY role on machine-authored documents, and that is
    deliberate — it replaces the earlier additive design.

    Retrieval matches roles by overlap (`jsonb_exists_any`) and has no NOT
    clause, so exclusion cannot be expressed by subtracting a tag. The only
    way to make these documents absent by default is to withhold their role
    from the default set: `_resolve_kb_roles` builds `allowed` from the
    caller's audience plus `system`, which cannot overlap ["generated"].

    Asking for them by name still works — the clamp permits `generated`
    explicitly. Absent unless requested, never unreachable.

    The earlier version of this file asserted the opposite (that `generated`
    must always be paired with an audience) because at that point nothing
    permitted it explicitly, so alone meant unreachable. Adding the opt-in is
    what changed the answer.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "src/noomesh/pipeline/research.py",
            "gateway-rust/src/heartbeat_actions.rs",
        ],
    )
    def test_writers_tag_generated_alone(self, path):
        src = (ROOT / path).read_text()
        assert '"roles": ["generated"]' in src, f"{path}: generated must be the only role"

    @staticmethod
    def _reader_roles(**params):
        """Resolve for a read-scope reader, as the bus now delivers them.

        The caller is no longer taken from the message body (an earlier changef
        R32) — `_resolve_kb_roles` reads the principal the worker pool
        verified from the signed header, and an absent one is refused. These
        cases are about the `generated` tag, not about identity plumbing, so
        the principal is supplied the way the header would have.
        """
        from noomesh.gateway import bus_principal as bp
        from noomesh.workers.kb import _resolve_kb_roles

        return _resolve_kb_roles({
            **params,
            "_requester": {"sub": "carol", "scopes": ["read"]},
            bp.PRINCIPAL_KEY: bp.Principal(
                sub="carol", kind="user", role="user", scopes=["read"]
            ),
        })

    def test_default_scope_excludes_generated(self):
        assert "generated" not in (self._reader_roles() or [])

    def test_generated_is_reachable_when_asked_for(self):
        got = self._reader_roles(roles=["generated"])
        assert got == ["generated"], "opting in must not be clamped away"

    def test_opting_in_grants_nothing_else(self):
        """The clamp still applies to every other role — `generated` is an
        exception for one tag, not a hole."""
        got = self._reader_roles(roles=["generated", "user:alice", "team:secret"])
        assert got == ["generated"]
