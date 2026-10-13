# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for evidence model and factory."""

from noomesh.memory.evidence import Evidence, evidence_from_chunk


class TestEvidence:
    """Test Evidence dataclass."""

    def test_creation(self):
        e = Evidence(
            source_type="page",
            doc_id="doc-1",
            page_no=3,
            page_id="page-3",
            snippet="some text here",
            span=(10, 25),
            confidence=0.85,
        )
        assert e.source_type == "page"
        assert e.doc_id == "doc-1"
        assert e.confidence == 0.85

    def test_to_dict(self):
        e = Evidence(
            source_type="chunk",
            doc_id="doc-2",
            page_no=1,
            page_id="page-1",
            snippet="hello world",
            span=(0, 11),
            confidence=0.9,
        )
        d = e.to_dict()
        assert d["source_type"] == "chunk"
        assert d["span"] == [0, 11]  # tuple -> list
        assert d["confidence"] == 0.9
        assert d["snippet"] == "hello world"

    def test_to_dict_all_fields(self):
        e = Evidence(
            source_type="graph_edge",
            doc_id="d",
            page_no=0,
            page_id="p",
            snippet="s",
            span=(5, 10),
            confidence=0.5,
        )
        d = e.to_dict()
        assert set(d.keys()) == {
            "source_type", "doc_id", "page_no", "page_id",
            "snippet", "span", "confidence",
        }


class TestEvidenceFromChunk:
    """Test evidence_from_chunk factory function."""

    def test_with_explicit_offsets(self):
        chunk = {
            "text": "target text",
            "page_id": "page-1",
            "score": 0.75,
            "start_char": 20,
            "end_char": 31,
        }
        page = {
            "doc_id": "doc-1",
            "page_id": "page-1",
            "page_no": 2,
            "text": "0123456789012345678target text and more",
        }
        e = evidence_from_chunk(chunk, page)
        assert e.source_type == "chunk"
        assert e.span == (20, 31)
        assert e.confidence == 0.75
        assert e.snippet == "target text"

    def test_without_offsets_finds_in_page(self):
        chunk = {"text": "needle", "page_id": "p1", "score": 0.8}
        page = {
            "doc_id": "d1",
            "page_id": "p1",
            "page_no": 1,
            "text": "haystack needle trailing",
        }
        e = evidence_from_chunk(chunk, page)
        assert e.span == (9, 15)  # "needle" at index 9

    def test_without_offsets_not_found(self):
        chunk = {"text": "missing", "page_id": "p1", "score": 0.6}
        page = {"doc_id": "d1", "page_id": "p1", "page_no": 1, "text": "no match here"}
        e = evidence_from_chunk(chunk, page)
        assert e.span == (0, 7)  # fallback: (0, len(chunk_text))

    def test_confidence_override(self):
        chunk = {"text": "a", "page_id": "p1", "score": 0.5}
        page = {"doc_id": "d1", "page_id": "p1", "page_no": 1, "text": "a"}
        e = evidence_from_chunk(chunk, page, confidence=0.99)
        assert e.confidence == 0.99

    def test_missing_page_fields(self):
        chunk = {"text": "x", "page_id": "p1", "score": 0.1}
        page = {}
        e = evidence_from_chunk(chunk, page)
        assert e.doc_id == ""
        assert e.page_no == 0
        assert e.page_id == "p1"  # falls back to chunk's page_id
