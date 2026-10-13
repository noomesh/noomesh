# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for RAG orchestrator."""
import pytest
from unittest.mock import MagicMock

from noomesh.memory.evidence import Evidence
from noomesh.memory.rag_orchestrator import (
    Citation,
    RAGOrchestrator,
    RAGResponse,
)


def _make_evidence(snippet: str, confidence: float = 0.9) -> Evidence:
    return Evidence(
        source_type="chunk",
        doc_id="d1",
        page_no=1,
        page_id="p1",
        snippet=snippet,
        span=(0, len(snippet)),
        confidence=confidence,
    )


def _make_evidence_pack(
    page_id: str = "p1",
    doc_id: str = "d1",
    title: str = "Test Doc",
    page_no: int = 1,
    page_text: str = "Full page text here",
    evidence_items: list = None,
    relevance_score: float = 0.8,
):
    """Create a mock EvidencePack."""
    pack = MagicMock()
    pack.page_id = page_id
    pack.doc_id = doc_id
    pack.title = title
    pack.page_no = page_no
    pack.page_text = page_text
    pack.evidence_items = evidence_items or [_make_evidence("snippet text")]
    pack.relevance_score = relevance_score
    return pack


# ── I/O Spec: intent classification ───────────────────────────────
# Each question MUST classify to the specified intent.
# Intent determines retrieval strategy:
#   why/troubleshooting → graph_first (follow entity relationships)
#   comparison          → hybrid (graph + unrestricted)
#   lookup              → lookup (vector search only)
#   explanation         → hybrid (default)

_INTENT_SPEC = [
    # id                    question                                    expected_intent
    ("why_keyword",         "Why does this happen?",                    "why"),
    ("cause_keyword",       "What caused the failure?",                 "why"),
    ("reason_keyword",      "What is the reason for this?",             "why"),
    ("compare_keyword",     "Compare Python vs Java",                   "comparison"),
    ("difference_keyword",  "What is the difference between X and Y?",  "comparison"),
    ("versus_keyword",      "React versus Angular for web apps",        "comparison"),
    ("what_is_keyword",     "What is machine learning?",                "lookup"),
    ("define_keyword",      "Define gradient descent",                  "lookup"),
    ("how_many_keyword",    "How many layers does BERT have?",          "lookup"),
    ("fix_keyword",         "How do I fix this error?",                 "troubleshooting"),
    ("error_keyword",       "I'm getting a connection error",           "troubleshooting"),
    ("debug_keyword",       "Help me debug this crash",                 "troubleshooting"),
    ("no_keyword_match",    "Tell me about neural networks",            "explanation"),
    ("generic_question",    "Explain transformers in NLP",              "explanation"),
]


class TestClassifyIntentSpec:
    @pytest.mark.parametrize(
        "question,expected_intent",
        [row[1:] for row in _INTENT_SPEC],
        ids=[row[0] for row in _INTENT_SPEC],
    )
    def test_intent_classification(self, question, expected_intent):
        orch = RAGOrchestrator(MagicMock(), MagicMock(), MagicMock())
        assert orch.classify_intent(question) == expected_intent


class TestBuildCitations:
    """Test citation building from evidence packs."""

    def test_build_from_evidence_items(self):
        evidence = _make_evidence("test snippet", confidence=0.85)
        pack = _make_evidence_pack(
            page_id="p1", doc_id="d1", title="Doc", page_no=3,
            evidence_items=[evidence],
        )
        citations = RAGOrchestrator._build_citations([pack])
        assert len(citations) == 1
        assert citations[0].doc_id == "d1"
        assert citations[0].page_no == 3
        assert citations[0].excerpt == "test snippet"
        assert citations[0].confidence == 0.85

    def test_build_from_empty_evidence_items(self):
        pack = MagicMock()
        pack.page_id = "p2"
        pack.doc_id = "d2"
        pack.title = "Other"
        pack.page_no = 1
        pack.page_text = "Page text content here"
        pack.evidence_items = []
        pack.relevance_score = 0.8

        citations = RAGOrchestrator._build_citations([pack])
        assert len(citations) == 1
        assert citations[0].excerpt == "Page text content here"
        assert citations[0].confidence == 0.8

    def test_empty_evidence(self):
        citations = RAGOrchestrator._build_citations([])
        assert citations == []


class TestMergeEvidence:
    """Test evidence merging and deduplication."""

    def test_primary_takes_precedence(self):
        p1 = _make_evidence_pack(page_id="p1")
        p2 = _make_evidence_pack(page_id="p1")  # duplicate
        p3 = _make_evidence_pack(page_id="p3")

        merged = RAGOrchestrator._merge_evidence([p1], [p2, p3])
        page_ids = [m.page_id for m in merged]
        assert "p1" in page_ids
        assert "p3" in page_ids
        assert len(merged) == 2  # p1 only appears once

    def test_max_total_cap(self):
        packs = [_make_evidence_pack(page_id=f"p{i}") for i in range(15)]
        merged = RAGOrchestrator._merge_evidence(packs, [], max_total=5)
        assert len(merged) == 5

    def test_empty_merge(self):
        merged = RAGOrchestrator._merge_evidence([], [])
        assert merged == []


class TestCollectEvidenceItems:
    """Test evidence item flattening."""

    def test_flatten(self):
        e1 = _make_evidence("snippet 1")
        e2 = _make_evidence("snippet 2")
        e3 = _make_evidence("snippet 3")
        packs = [
            _make_evidence_pack(evidence_items=[e1, e2]),
            _make_evidence_pack(evidence_items=[e3]),
        ]
        items = RAGOrchestrator._collect_evidence_items(packs)
        assert len(items) == 3

    def test_empty_packs(self):
        pack = MagicMock()
        pack.evidence_items = []
        items = RAGOrchestrator._collect_evidence_items([pack])
        assert items == []


class TestCitationDataclass:
    """Test Citation dataclass."""

    def test_creation(self):
        c = Citation(
            doc_id="d1",
            title="Test",
            page_no=1,
            page_id="p1",
            excerpt="some text",
        )
        assert c.confidence == 0.0
        assert c.span == []

    def test_with_span(self):
        c = Citation(
            doc_id="d1",
            title="Test",
            page_no=1,
            page_id="p1",
            excerpt="some text",
            span=[10, 20],
            confidence=0.95,
        )
        assert c.span == [10, 20]
        assert c.confidence == 0.95


class TestRAGResponse:
    """Test RAGResponse dataclass."""

    def test_defaults(self):
        r = RAGResponse(answer="")
        assert r.evidence == []
        assert r.graph_context is None
        assert r.strategy_used == ""
        assert r.intent == ""
        assert r.citations == []
        assert r.verification is None
        assert r.hypotheses == []
