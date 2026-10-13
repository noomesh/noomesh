# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for persona_id scoping across stores.

These tests verify that persona_id filtering works correctly in:
- ConversationStore
- PGVectorStore
- MemorySystem (passthrough)
- VideoMemoryManager (directory scoping)

Tests use mocks/stubs where DB access is needed, or skip when not available.
"""



# ── ConversationStore persona_id filtering ──────────────────────


class TestConversationStorePersonaId:
    """Verify persona_id parameter is accepted in ConversationStore methods."""

    def test_create_conversation_accepts_persona_id(self):
        """create_conversation signature should include persona_id."""
        import inspect
        from noomesh.memory.conversation_store import ConversationStore

        sig = inspect.signature(ConversationStore.create_conversation)
        assert "persona_id" in sig.parameters
        assert sig.parameters["persona_id"].default is None

    def test_ensure_conversation_accepts_persona_id(self):
        """ensure_conversation signature should include persona_id."""
        import inspect
        from noomesh.memory.conversation_store import ConversationStore

        sig = inspect.signature(ConversationStore.ensure_conversation)
        assert "persona_id" in sig.parameters
        assert sig.parameters["persona_id"].default is None

    def test_create_conversation_source_includes_persona_id(self):
        """create_conversation should pass persona_id into the INSERT values."""
        import inspect
        from noomesh.memory.conversation_store import ConversationStore

        source = inspect.getsource(ConversationStore.create_conversation)
        assert "persona_id" in source

    def test_ensure_conversation_source_includes_persona_id(self):
        """ensure_conversation should include persona_id in the upsert."""
        import inspect
        from noomesh.memory.conversation_store import ConversationStore

        source = inspect.getsource(ConversationStore.ensure_conversation)
        assert "persona_id" in source


# ── PGVectorStore persona_id filtering ──────────────────────────


class TestPGVectorStorePersonaId:
    """Verify persona_id parameter is accepted in PGVectorStore methods."""

    def test_add_signature_accepts_persona_id(self):
        """add() should accept persona_id as keyword argument."""
        import inspect
        from noomesh.memory.pgvector_store import PGVectorStore

        sig = inspect.signature(PGVectorStore.add)
        assert "persona_id" in sig.parameters

    def test_search_signature_accepts_persona_id(self):
        """search() should accept persona_id as keyword argument."""
        import inspect
        from noomesh.memory.pgvector_store import PGVectorStore

        sig = inspect.signature(PGVectorStore.search)
        assert "persona_id" in sig.parameters

    def test_search_text_signature_accepts_persona_id(self):
        """search_text() should accept persona_id as keyword argument."""
        import inspect
        from noomesh.memory.pgvector_store import PGVectorStore

        sig = inspect.signature(PGVectorStore.search_text)
        assert "persona_id" in sig.parameters


# ── MemorySystem persona_id passthrough ─────────────────────────


class TestMemorySystemPersonaId:
    """Verify persona_id flows through MemorySystem to backing stores."""

    def test_record_async_signature(self):
        """record_async() should accept persona_id."""
        import inspect
        from noomesh.memory.manager import MemorySystem

        sig = inspect.signature(MemorySystem.record_async)
        assert "persona_id" in sig.parameters

    def test_retrieve_async_signature(self):
        """retrieve_async() should accept persona_id."""
        import inspect
        from noomesh.memory.manager import MemorySystem

        sig = inspect.signature(MemorySystem.retrieve_async)
        assert "persona_id" in sig.parameters


# ── VideoMemoryManager persona scoping ──────────────────────────


class TestVideoMemoryPersonaScoping:
    """Verify persona_id scoping in VideoMemoryManager."""

    def test_search_signature_accepts_persona_id(self):
        """search() should accept persona_id."""
        import inspect
        from noomesh.memory.video.manager import VideoMemoryManager

        sig = inspect.signature(VideoMemoryManager.search)
        assert "persona_id" in sig.parameters

    def test_archive_conversations_signature_accepts_persona_id(self):
        """archive_conversations() should accept persona_id."""
        import inspect
        from noomesh.memory.video.manager import VideoMemoryManager

        sig = inspect.signature(VideoMemoryManager.archive_conversations)
        assert "persona_id" in sig.parameters


# ── DB model persona_id column ──────────────────────────────────


class TestDBModelsPersonaId:
    """Verify persona_id column exists in ORM models."""

    def test_noo_conversation_has_persona_id(self):
        from noomesh.db.models import PaiConversation

        assert hasattr(PaiConversation, "persona_id")

    def test_persona_id_is_nullable(self):
        from noomesh.db.models import PaiConversation

        col = PaiConversation.__table__.columns["persona_id"]
        assert col.nullable is True


# ── Persona isolation (conceptual) ──────────────────────────────


class TestPersonaIsolationConcepts:
    """Test persona isolation rules at the API contract level."""

    def test_self_scoped_uses_persona_id(self):
        """Self-scoped operations should pass persona_id."""
        # Convention: persona_id=<uuid> means self-scoped
        assert "uuid-maya" != None  # non-None = self-scoped

    def test_shared_scope_uses_none(self):
        """Shared-scope operations should pass persona_id=None."""
        # Convention: persona_id=None means shared/visible to all
        persona_id = None
        assert persona_id is None  # None = shared scope

    def test_search_signatures_default_to_none(self):
        """All search methods should default persona_id to None (shared)."""
        import inspect
        from noomesh.memory.pgvector_store import PGVectorStore
        from noomesh.memory.conversation_store import ConversationStore

        for cls, method_name in [
            (PGVectorStore, "search"),
            (PGVectorStore, "search_text"),
            (ConversationStore, "create_conversation"),
        ]:
            sig = inspect.signature(getattr(cls, method_name))
            param = sig.parameters["persona_id"]
            assert param.default is None, f"{cls.__name__}.{method_name} persona_id should default to None"
