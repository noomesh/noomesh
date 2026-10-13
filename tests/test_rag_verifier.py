# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for RAG verifier.

Spec: The verifier checks claims against evidence using two passes:
  Pass 1: Key-phrase matching (3+ word sequences from claim found in evidence)
  Pass 2: Content-word overlap (>= 40% of 4+ char words found in evidence)

Status thresholds:
  confidence >= 0.8  → "approved"
  confidence >= 0.3  → "partial"
  confidence < 0.3   → "rejected"

Claims shorter than 10 characters are filtered out.
"""
import pytest

from noomesh.memory.evidence import Evidence
from noomesh.memory.rag_verifier import RAGVerifier


@pytest.fixture
def verifier():
    return RAGVerifier()


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


# ── I/O Spec: claim support detection ─────────────────────────────
# Each row: (claim, evidence_texts, expected_supported)
#
# Rules:
#   - 3+ word phrase from claim found in evidence → supported
#   - >= 40% content word overlap → supported
#   - Neither → not supported

_CLAIM_SUPPORT_SPEC = [
    # id                       claim                                      evidence                                                  expected
    ("exact_phrase",           "Python is a popular language",            ["python is a popular language used worldwide"],            True),
    ("phrase_subset",          "machine learning models are powerful",    ["machine learning models are powerful and scalable"],      True),
    ("word_overlap_above_40",  "machine learning models require data",   ["the training data for machine learning algorithms"],      True),
    ("no_overlap",             "quantum computing advances rapidly",     ["classical algorithms run on normal hardware"],            False),
    ("partial_overlap_below",  "quantum cryptography breaks everything", ["quantum physics experiments in laboratory"],              False),
    ("empty_evidence",         "some claim about something important",   [],                                                        False),
]


class TestClaimSupportSpec:
    @pytest.mark.parametrize(
        "claim,evidence_texts,expected",
        [row[1:] for row in _CLAIM_SUPPORT_SPEC],
        ids=[row[0] for row in _CLAIM_SUPPORT_SPEC],
    )
    def test_is_claim_supported(self, claim, evidence_texts, expected):
        assert RAGVerifier._is_claim_supported(claim, evidence_texts) is expected


# ── I/O Spec: verification status thresholds ──────────────────────
# Each row: (description, n_supported, n_unsupported, expected_status)
#
# confidence = n_supported / (n_supported + n_unsupported)
# Status:  >= 0.8 → approved,  >= 0.3 → partial,  < 0.3 → rejected

_STATUS_SPEC = [
    ("all_supported",    5, 0, "approved"),   # 1.0
    ("mostly_supported", 4, 1, "approved"),   # 0.8
    ("half_and_half",    2, 2, "partial"),     # 0.5
    ("mostly_unsupported", 1, 3, "partial"),  # 0.25 — but >= 0.3? No, 0.25 < 0.3 → rejected
    ("none_supported",   0, 3, "rejected"),   # 0.0
]


class TestVerificationStatusSpec:
    @pytest.mark.parametrize(
        "n_supported,n_unsupported,expected_status",
        [row[1:] for row in _STATUS_SPEC],
        ids=[row[0] for row in _STATUS_SPEC],
    )
    def test_status_threshold(self, verifier, n_supported, n_unsupported, expected_status):
        # Build evidence that supports exactly n_supported claims
        supported_evidence = [
            _make_evidence(f"supported claim number {i} with enough words to match")
            for i in range(n_supported)
        ]
        supported_claims = [
            f"supported claim number {i} with enough words to match"
            for i in range(n_supported)
        ]
        unsupported_claims = [
            f"completely unrelated topic {i} about quantum blockchain"
            for i in range(n_unsupported)
        ]
        result = verifier.verify_with_evidence(
            supported_evidence, supported_claims + unsupported_claims
        )
        # Fix: 1/4 = 0.25 < 0.3, so "mostly_unsupported" is actually "rejected"
        if n_supported == 1 and n_unsupported == 3:
            assert result.status == "rejected"
        else:
            assert result.status == expected_status


class TestVerifyEdgeCases:
    """Test edge cases in verification."""

    def test_no_claims_is_approved(self, verifier):
        evidence = [_make_evidence("some text")]
        result = verifier.verify_with_evidence(evidence, [])
        assert result.status == "approved"
        assert result.confidence == 1.0

    def test_short_claims_filtered(self, verifier):
        evidence = [_make_evidence("text")]
        result = verifier.verify_with_evidence(evidence, ["short", "ok"])
        assert result.status == "approved"  # all claims < 10 chars

    def test_unsupported_generates_retrieval_hints(self, verifier):
        evidence = [_make_evidence("Python programming language")]
        claims = ["Quantum computing will revolutionize cryptography entirely"]
        result = verifier.verify_with_evidence(evidence, claims)
        assert len(result.required_retrieval) > 0


class TestExtractRetrievalTerms:
    """Test key-term extraction for re-retrieval."""

    def test_extracts_bigrams(self):
        terms = RAGVerifier._extract_retrieval_terms(
            "distributed consensus mechanisms in blockchain"
        )
        assert len(terms) > 0
        # Should have bigrams of content words
        assert any(" " in t for t in terms)

    def test_extracts_long_words(self):
        terms = RAGVerifier._extract_retrieval_terms(
            "cryptography implementation details"
        )
        # "cryptography" and "implementation" are >= 6 chars
        long_words = [t for t in terms if " " not in t]
        assert len(long_words) > 0

    def test_caps_at_five(self):
        terms = RAGVerifier._extract_retrieval_terms(
            "distributed consensus mechanisms blockchain technology implementation security"
        )
        assert len(terms) <= 5


class TestSplitSentences:
    """Test sentence splitting."""

    def test_split_on_period(self):
        sentences = RAGVerifier._split_sentences("Hello world. How are you? Fine!")
        assert len(sentences) == 3

    def test_single_sentence(self):
        sentences = RAGVerifier._split_sentences("No punctuation at end")
        assert len(sentences) == 1

    def test_empty_string(self):
        sentences = RAGVerifier._split_sentences("")
        assert len(sentences) == 0
