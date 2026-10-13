# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""E2E tests for the persona endpoints (gateway-URL gated).

Updated 2026-08-08 for the Rust surface: `GET /api/persona/` returns
`{"personas": [...], "active_detail": ...}` (routes/agents.rs), not the
bare list the Python gateway served. The persona *chat* and *lens*
routes were deleted in 4190a00 — they imported a module that never
existed and had only ever returned 400 — so their tests are gone with
them, not skipped.
"""

import httpx
import pytest


@pytest.mark.integration
class TestPersonaE2E:
    """Integration tests for /api/persona endpoints."""

    @pytest.fixture
    def client(self, gateway_url):
        return httpx.AsyncClient(base_url=gateway_url, timeout=60.0)

    @pytest.mark.asyncio
    async def test_list_personas(self, client):
        """GET /api/persona/ returns the wrapped personas envelope."""
        async with client:
            resp = await client.get("/api/persona/")
        assert resp.status_code == 200
        data = resp.json()
        assert "personas" in data
        assert isinstance(data["personas"], list)
        if data["personas"]:
            assert "persona_id" in data["personas"][0]
            assert "name" in data["personas"][0]

    @pytest.mark.asyncio
    async def test_get_persona_detail(self, client):
        """GET /api/persona/{id} should return persona details."""
        async with client:
            list_resp = await client.get("/api/persona/")
            personas = (
                list_resp.json().get("personas", [])
                if list_resp.status_code == 200 else []
            )
            if not personas:
                pytest.skip("No personas available")

            persona_id = personas[0]["persona_id"]
            resp = await client.get(f"/api/persona/{persona_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["persona_id"] == persona_id
        assert "name" in data

    @pytest.mark.asyncio
    async def test_get_persona_not_found(self, client):
        """GET /api/persona/nonexistent should return 404."""
        async with client:
            resp = await client.get("/api/persona/nonexistent-id")
        assert resp.status_code == 404
